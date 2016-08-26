/*
 * Copyright (c) 2008, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) Allen Kay <allen.m.kay@intel.com>
 * Copyright (C) Weidong Han <weidong.han@intel.com>
 */

#include <xen/sched.h>
#include <xen/softirq.h>
#include <xen/domain_page.h>
#include <asm/paging.h>
#include <xen/iommu.h>
#include <xen/irq.h>
#include <xen/numa.h>
#include <asm/fixmap.h>
#include <asm/setup.h>
#include "../iommu.h"
#include "../dmar.h"
#include "../vtd.h"
#include "../extern.h"

/* gpu's separated high-mem iommu page directory machine address */
u64 gpu_pgd_maddr = 0;
/* gpu's separated low-mem iommu page directory machine address per domain */
u64 dom_gpu_pgd_maddr[] = { [0 ... GPU_MAX_DOM - 1] = 0};

/*
 * iommu_inclusive_mapping: when set, all memory below 4GB is included in dom0
 * 1:1 iommu mappings except xen and unusable regions.
 */
static bool_t __hwdom_initdata iommu_inclusive_mapping = 1;
boolean_param("iommu_inclusive_mapping", iommu_inclusive_mapping);

void *map_vtd_domain_page(u64 maddr)
{
    return map_domain_page(_mfn(paddr_to_pfn(maddr)));
}

void unmap_vtd_domain_page(void *va)
{
    unmap_domain_page(va);
}

unsigned int get_cache_line_size(void)
{
    return ((cpuid_ebx(1) >> 8) & 0xff) * 8;
}

void cacheline_flush(char * addr)
{
    clflush(addr);
}

void flush_all_cache()
{
    wbinvd();
}

static int _hvm_dpci_isairq_eoi(struct domain *d,
                                struct hvm_pirq_dpci *pirq_dpci, void *arg)
{
    struct hvm_irq *hvm_irq = &d->arch.hvm_domain.irq;
    unsigned int isairq = (long)arg;
    const struct dev_intx_gsi_link *digl;

    list_for_each_entry ( digl, &pirq_dpci->digl_list, list )
    {
        unsigned int link = hvm_pci_intx_link(digl->device, digl->intx);

        if ( hvm_irq->pci_link.route[link] == isairq )
        {
            hvm_pci_intx_deassert(d, digl->device, digl->intx);
            if ( --pirq_dpci->pending == 0 )
            {
                stop_timer(&pirq_dpci->timer);
                pirq_guest_eoi(dpci_pirq(pirq_dpci));
            }
        }
    }

    return 0;
}

void hvm_dpci_isairq_eoi(struct domain *d, unsigned int isairq)
{
    struct hvm_irq_dpci *dpci = NULL;

    ASSERT(isairq < NR_ISAIRQS);
    if ( !iommu_enabled)
        return;

    spin_lock(&d->event_lock);

    dpci = domain_get_irq_dpci(d);

    if ( dpci && test_bit(isairq, dpci->isairq_map) )
    {
        /* Multiple mirq may be mapped to one isa irq */
        pt_pirq_iterate(d, _hvm_dpci_isairq_eoi, (void *)(long)isairq);
    }
    spin_unlock(&d->event_lock);
}

void __hwdom_init vtd_set_hwdom_mapping(struct domain *d)
{
    unsigned long i, j, tmp, top;

    BUG_ON(!is_hardware_domain(d));

    top = max(max_pdx, pfn_to_pdx(0xffffffffUL >> PAGE_SHIFT) + 1);

    /*
    printk("xuyu: (%s:%d) max_pdx: %lx, top: %lx, hap_enabled: %s, iommu_hap_pt_share: %s\n",
            __FUNCTION__, __LINE__, max_pdx, top,
            hap_enabled(d) ? "enabled" : "disabled",
            iommu_hap_pt_share ? "enabled" : "disabled");
    */

    for ( i = 0; i < top; i++ )
    {
        /*
         * Set up 1:1 mapping for dom0. Default to use only conventional RAM
         * areas and let RMRRs include needed reserved regions. When set, the
         * inclusive mapping maps in everything below 4GB except unusable
         * ranges.
         */
        unsigned long pfn = pdx_to_pfn(i);

        if ( pfn > (0xffffffffUL >> PAGE_SHIFT) ?
             (!mfn_valid(pfn) ||
              !page_is_ram_type(pfn, RAM_TYPE_CONVENTIONAL)) :
             iommu_inclusive_mapping ?
             page_is_ram_type(pfn, RAM_TYPE_UNUSABLE) :
             !page_is_ram_type(pfn, RAM_TYPE_CONVENTIONAL) )
            continue;

        /* Exclude Xen bits */
        if ( xen_in_range(pfn) )
            continue;

        tmp = 1 << (PAGE_SHIFT - PAGE_SHIFT_4K);
        for ( j = 0; j < tmp; j++ )
            iommu_map_page(d, pfn * tmp + j, pfn * tmp + j,
                           IOMMUF_readable|IOMMUF_writable);

        if (!(i & (0xfffff >> (PAGE_SHIFT - PAGE_SHIFT_4K))))
            process_pending_softirqs();
    }
}

/*
 * map the whole gpu space by one specified offset [pfn]
 */
void vtd_map_gpu_space_by_offset(struct domain *d, unsigned long offset)
{
    unsigned long i, j, tmp, top;
    BUG_ON(!is_hardware_domain(d));

    top = max(max_pdx, pfn_to_pdx(0xffffffffUL >> PAGE_SHIFT) + 1);

    for ( i = 0; i < top; i++ )
    {
        unsigned long pfn = pdx_to_pfn(i);
        if ( pfn > (0xffffffffUL >> PAGE_SHIFT) ?
             (!mfn_valid(pfn) ||
              !page_is_ram_type(pfn, RAM_TYPE_CONVENTIONAL)) :
             iommu_inclusive_mapping ?
             page_is_ram_type(pfn, RAM_TYPE_UNUSABLE) :
             !page_is_ram_type(pfn, RAM_TYPE_CONVENTIONAL) )
            continue;

        /* Exclude Xen bits */
        if ( xen_in_range(pfn) )
            continue;

        tmp = 1 << (PAGE_SHIFT - PAGE_SHIFT_4K);
        for ( j = 0; j < tmp; j++ )
            iommu_gpu_map_page(d, offset + pfn * tmp + j, pfn * tmp + j,
                           IOMMUF_readable|IOMMUF_writable);

        if (!(i & (0xfffff >> (PAGE_SHIFT - PAGE_SHIFT_4K))))
            process_pending_softirqs();
    }

    /*
    printk("xuyu: (%s:%d) gpu space remapping is done, offset: %lx\n",
            __FUNCTION__, __LINE__, offset);
    */
}

void __hwdom_init vtd_set_hwdom_gpu_mapping(struct domain *d)
{
    ASSERT(d == hardware_domain);
    /* dom0 map [0, max_mem] to [0, max_mem] */
    vtd_map_gpu_space_by_offset(d, 0);
    /* gpu map [128G, 128G + max_mem] to [0, max_mem] */
    vtd_map_gpu_space_by_offset(d, (1UL << GPU_HIGH_BIT_SHIFT) >> PAGE_SHIFT);
    /* switch gpu's low memory to dom0's, initially */
    iommu_switch_gpu_iopt(d->domain_id);
}
