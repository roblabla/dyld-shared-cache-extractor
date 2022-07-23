use std::fmt::Debug;
use object::read::macho::*;
use object::macho::*;
use object::{Endian, Pod};

pub trait EditableNlist: Debug + Pod + Nlist {
    fn set_n_strx(&mut self, endian: Self::Endian, n_strx: u32);
    fn set_n_type(&mut self, n_type: u8);
    fn set_n_sect(&mut self, n_sect: u8);
    fn set_n_desc(&mut self, endian: Self::Endian, n_desc: u16);
    fn set_n_value(&mut self, endian: Self::Endian, n_value: u64);
}
impl<E: Endian> EditableNlist for Nlist32<E> {
    fn set_n_strx(&mut self, endian: Self::Endian, n_strx: u32) {
        self.n_strx.set(endian, n_strx);
    }
    fn set_n_type(&mut self, n_type: u8) {
        self.n_type = n_type;
    }
    fn set_n_sect(&mut self, n_sect: u8) {
        self.n_sect = n_sect;
    }
    fn set_n_desc(&mut self, endian: Self::Endian, n_desc: u16) { 
        self.n_desc.set(endian, n_desc);
    }
    fn set_n_value(&mut self, endian: Self::Endian, n_value: u64) {
        self.n_value.set(endian, n_value as u32);
    }
}
impl<E: Endian> EditableNlist for Nlist64<E> {
    fn set_n_strx(&mut self, endian: Self::Endian, n_strx: u32) {
        self.n_strx.set(endian, n_strx);
    }
    fn set_n_type(&mut self, n_type: u8) {
        self.n_type = n_type;
    }
    fn set_n_sect(&mut self, n_sect: u8) {
        self.n_sect = n_sect;
    }
    fn set_n_desc(&mut self, endian: Self::Endian, n_desc: u16) { 
        self.n_desc.set(endian, n_desc);
    }
    fn set_n_value(&mut self, endian: Self::Endian, n_value: u64) {
        self.n_value.set(endian, n_value);
    }
}


pub trait EditableSection: Debug + Pod + Section {
    fn set_sectname(&mut self, sectname: [u8; 16]);
    fn set_segname(&mut self, segname: [u8; 16]);
    fn set_addr(&mut self, endian: Self::Endian, addr: u64);
    fn set_size(&mut self, endian: Self::Endian, size: u64);
    fn set_offset(&mut self, endian: Self::Endian, offset: u32);
    fn set_align(&mut self, endian: Self::Endian, align: u32);
    fn set_reloff(&mut self, endian: Self::Endian, reloff: u32);
    fn set_nreloc(&mut self, endian: Self::Endian, nreloc: u32);
    fn set_flags(&mut self, endian: Self::Endian, flags: u32);
}
impl<E: Endian> EditableSection for Section32<E> {
    fn set_sectname(&mut self, sectname: [u8; 16]) {
        self.sectname = sectname;
    }
    fn set_segname(&mut self, segname: [u8; 16]) {
        self.segname = segname;
    }
    fn set_addr(&mut self, endian: Self::Endian, addr: u64) {
        self.addr.set(endian, addr as u32);
    }
    fn set_size(&mut self, endian: Self::Endian, size: u64) {
        self.size.set(endian, size as u32);
    }
    fn set_offset(&mut self, endian: Self::Endian, offset: u32) {
        self.offset.set(endian, offset);
    }
    fn set_align(&mut self, endian: Self::Endian, align: u32) {
        self.align.set(endian, align);
    }
    fn set_reloff(&mut self, endian: Self::Endian, reloff: u32) {
        self.reloff.set(endian, reloff);
    }
    fn set_nreloc(&mut self, endian: Self::Endian, nreloc: u32) {
        self.nreloc.set(endian, nreloc);
    }
    fn set_flags(&mut self, endian: Self::Endian, flags: u32) {
        self.flags.set(endian, flags);
    }
}
impl<E: Endian> EditableSection for Section64<E> {
    fn set_sectname(&mut self, sectname: [u8; 16]) {
        self.sectname = sectname;
    }
    fn set_segname(&mut self, segname: [u8; 16]) {
        self.segname = segname;
    }
    fn set_addr(&mut self, endian: Self::Endian, addr: u64) {
        self.addr.set(endian, addr);
    }
    fn set_size(&mut self, endian: Self::Endian, size: u64) {
        self.size.set(endian, size);
    }
    fn set_offset(&mut self, endian: Self::Endian, offset: u32) {
        self.offset.set(endian, offset);
    }
    fn set_align(&mut self, endian: Self::Endian, align: u32) {
        self.align.set(endian, align);
    }
    fn set_reloff(&mut self, endian: Self::Endian, reloff: u32) {
        self.reloff.set(endian, reloff);
    }
    fn set_nreloc(&mut self, endian: Self::Endian, nreloc: u32) {
        self.nreloc.set(endian, nreloc);
    }
    fn set_flags(&mut self, endian: Self::Endian, flags: u32) {
        self.flags.set(endian, flags);
    }
}

pub trait EditableSegment: Debug + Pod + Segment<Section = Self::EditableSection> {
    type EditableSection: EditableSection<Endian = Self::Endian>;

    fn set_cmd(&mut self, endian: Self::Endian, cmd: u32);
    fn set_cmdsize(&mut self, endian: Self::Endian, cmdsize: u32);
    fn set_segname(&mut self, segname: [u8; 16]);
    fn set_vmaddr(&mut self, endian: Self::Endian, vmaddr: u64);
    fn set_vmsize(&mut self, endian: Self::Endian, vmsize: u64);
    fn set_fileoff(&mut self, endian: Self::Endian, fileoff: u64);
    fn set_filesize(&mut self, endian: Self::Endian, filesize: u64);
    fn set_maxprot(&mut self, endian: Self::Endian, maxprot: u32);
    fn set_initprot(&mut self, endian: Self::Endian, initprot: u32);
    fn set_nsects(&mut self, endian: Self::Endian, nsects: u32);
    fn set_flags(&mut self, endian: Self::Endian, flags: u32);
}
impl<E: Endian> EditableSegment for SegmentCommand32<E> {
    type EditableSection = Section32<E>;

    fn set_cmd(&mut self, endian: Self::Endian, cmd: u32) {
        self.cmd.set(endian, cmd);
    }
    fn set_cmdsize(&mut self, endian: Self::Endian, cmdsize: u32) {
        self.cmdsize.set(endian, cmdsize);
    }
    fn set_segname(&mut self, segname: [u8; 16]) {
        self.segname = segname;
    }
    fn set_vmaddr(&mut self, endian: Self::Endian, vmaddr: u64) {
        self.vmaddr.set(endian, vmaddr as u32);
    }
    fn set_vmsize(&mut self, endian: Self::Endian, vmsize: u64) {
        self.vmsize.set(endian, vmsize as u32);
    }
    fn set_fileoff(&mut self, endian: Self::Endian, fileoff: u64) {
        self.fileoff.set(endian, fileoff as u32);
    }
    fn set_filesize(&mut self, endian: Self::Endian, filesize: u64) {
        self.filesize.set(endian, filesize as u32);
    }
    fn set_maxprot(&mut self, endian: Self::Endian, maxprot: u32) {
        self.maxprot.set(endian, maxprot);
    }
    fn set_initprot(&mut self, endian: Self::Endian, initprot: u32) {
        self.initprot.set(endian, initprot);
    }
    fn set_nsects(&mut self, endian: Self::Endian, nsects: u32) {
        self.nsects.set(endian, nsects);
    }
    fn set_flags(&mut self, endian: Self::Endian, flags: u32) {
        self.flags.set(endian, flags);
    }
}
impl<E: Endian> EditableSegment for SegmentCommand64<E> {
    type EditableSection = Section64<E>;

    fn set_cmd(&mut self, endian: Self::Endian, cmd: u32) {
        self.cmd.set(endian, cmd);
    }
    fn set_cmdsize(&mut self, endian: Self::Endian, cmdsize: u32) {
        self.cmdsize.set(endian, cmdsize);
    }
    fn set_segname(&mut self, segname: [u8; 16]) {
        self.segname = segname;
    }
    fn set_vmaddr(&mut self, endian: Self::Endian, vmaddr: u64) {
        self.vmaddr.set(endian, vmaddr);
    }
    fn set_vmsize(&mut self, endian: Self::Endian, vmsize: u64) {
        self.vmsize.set(endian, vmsize);
    }
    fn set_fileoff(&mut self, endian: Self::Endian, fileoff: u64) {
        self.fileoff.set(endian, fileoff);
    }
    fn set_filesize(&mut self, endian: Self::Endian, filesize: u64) {
        self.filesize.set(endian, filesize);
    }
    fn set_maxprot(&mut self, endian: Self::Endian, maxprot: u32) {
        self.maxprot.set(endian, maxprot);
    }
    fn set_initprot(&mut self, endian: Self::Endian, initprot: u32) {
        self.initprot.set(endian, initprot);
    }
    fn set_nsects(&mut self, endian: Self::Endian, nsects: u32) {
        self.nsects.set(endian, nsects);
    }
    fn set_flags(&mut self, endian: Self::Endian, flags: u32) {
        self.flags.set(endian, flags);
    }
}

pub trait EditableMachHeader: Debug + Pod + MachHeader<Segment = Self::EditableSegment, Section = Self::EditableSection, Nlist = Self::EditableNlist> {
    type EditableSegment: EditableSegment<Endian = Self::Endian, EditableSection = Self::EditableSection>;
    type EditableSection: EditableSection<Endian = Self::Endian>;
    type EditableNlist: EditableNlist<Endian = Self::Endian>;

    fn set_magic(&mut self, magic: u32);
    fn set_cputype(&mut self, endian: Self::Endian, cputype: u32);
    fn set_cpusubtype(&mut self, endian: Self::Endian, cpusubtype: u32);
    fn set_filetype(&mut self, endian: Self::Endian, filetype: u32);
    fn set_ncmds(&mut self, endian: Self::Endian, ncmds: u32);
    fn set_sizeofcmds(&mut self, endian: Self::Endian, sizeofcmds: u32);
    fn set_flags(&mut self, endian: Self::Endian, flags: u32);
}
impl<E: Endian> EditableMachHeader for MachHeader32<E> {
    type EditableSegment = SegmentCommand32<E>;
    type EditableSection = Section32<E>;
    type EditableNlist = Nlist32<E>;

    fn set_magic(&mut self, magic: u32) {
        self.magic.set(object::BigEndian, magic);
    }
    fn set_cputype(&mut self, endian: Self::Endian, cputype: u32) {
        self.cputype.set(endian, cputype);
    }
    fn set_cpusubtype(&mut self, endian: Self::Endian, cpusubtype: u32) {
        self.cpusubtype.set(endian, cpusubtype);
    }
    fn set_filetype(&mut self, endian: Self::Endian, filetype: u32) {
        self.filetype.set(endian, filetype);
    }
    fn set_ncmds(&mut self, endian: Self::Endian, ncmds: u32) {
        self.ncmds.set(endian, ncmds);
    }
    fn set_sizeofcmds(&mut self, endian: Self::Endian, sizeofcmds: u32) {
        self.sizeofcmds.set(endian, sizeofcmds);
    }
    fn set_flags(&mut self, endian: Self::Endian, flags: u32) {
        self.flags.set(endian, flags);
    }
}
impl<E: Endian> EditableMachHeader for MachHeader64<E> {
    type EditableSegment = SegmentCommand64<E>;
    type EditableSection = Section64<E>;
    type EditableNlist = Nlist64<E>;

    fn set_magic(&mut self, magic: u32) {
        self.magic.set(object::BigEndian, magic);
    }
    fn set_cputype(&mut self, endian: Self::Endian, cputype: u32) {
        self.cputype.set(endian, cputype);
    }
    fn set_cpusubtype(&mut self, endian: Self::Endian, cpusubtype: u32) {
        self.cpusubtype.set(endian, cpusubtype);
    }
    fn set_filetype(&mut self, endian: Self::Endian, filetype: u32) {
        self.filetype.set(endian, filetype);
    }
    fn set_ncmds(&mut self, endian: Self::Endian, ncmds: u32) {
        self.ncmds.set(endian, ncmds);
    }
    fn set_sizeofcmds(&mut self, endian: Self::Endian, sizeofcmds: u32) {
        self.sizeofcmds.set(endian, sizeofcmds);
    }
    fn set_flags(&mut self, endian: Self::Endian, flags: u32) {
        self.flags.set(endian, flags);
    }
}
