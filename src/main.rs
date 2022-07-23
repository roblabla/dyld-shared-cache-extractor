use object::endian::Endian;
use object::read::macho::*;
use object::Pod;
use object::write::WritableBuffer;
use object::{Endianness, ReadRef};
use std::borrow::Cow;
use std::fs;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::mem::{align_of, size_of, size_of_val};
use clap::Parser;

mod editable_macho;
use editable_macho::*;

mod trie;

#[derive(Parser)]
struct Args {
    #[clap(short, long)]
    list: bool,
    #[clap(short, long)]
    extract: Option<String>,
    file: PathBuf,
}

fn main() {
    let args = Args::parse();

    let file = match fs::File::open(&args.file) {
        Ok(file) => file,
        Err(err) => {
            println!("Failed to open file '{}': {}", args.file.display(), err,);
            return;
        }
    };
    let subcache_files = open_subcaches_if_exist(&args.file);
    let file = match unsafe { memmap2::Mmap::map(&file) } {
        Ok(mmap) => mmap,
        Err(err) => {
            println!("Failed to map file '{}': {}", args.file.display(), err,);
            return;
        }
    };
    let subcache_files: Option<Vec<_>> = subcache_files
        .into_iter()
        .map(
            |subcache_file| match unsafe { memmap2::Mmap::map(&subcache_file) } {
                Ok(mmap) => Some(mmap),
                Err(err) => {
                    eprintln!("Failed to map file '{}': {}", args.file.display(), err);
                    None
                }
            },
        )
        .collect();
    let subcache_files: Vec<&[u8]> = match &subcache_files {
        Some(subcache_files) => subcache_files
            .iter()
            .map(|subcache_file| &**subcache_file)
            .collect(),
        None => return,
    };

    let cache = match DyldCache::<Endianness>::parse(&*file, &subcache_files) {
        Ok(cache) => cache,
        Err(err) => {
            println!(
                "Failed to parse Dyld shared cache file '{}': {}",
                args.file.display(), err,
            );
            return;
        }
    };

    if args.list {
        // Print the list of image paths in this file.
        for image in cache.images() {
            if let Ok(path) = image.path() {
                println!("{}", path);
            }
        }
    }

    if let Some(extract) = args.extract {
        // Print the list of image paths in this file.
        for image in cache.images() {
            if let Ok(path) = image.path() {
                if path.ends_with(&extract) {
                    let out_file = std::fs::File::create(&extract).unwrap();
                    let mut stream = object::write::StreamingBuffer::new(out_file);

                    match cache.architecture().address_size() {
                        Some(object::AddressSize::U64) => {
                            handle_file::<object::macho::MachHeader64<Endianness>>(&mut stream, &cache, image)
                        }
                        Some(object::AddressSize::U32) => {
                            handle_file::<object::macho::MachHeader32<Endianness>>(&mut stream, &cache, image)
                        }
                        _ => panic!(),
                    };


                }
            }
        }

    }
}

#[derive(Debug, Clone)]
enum MyLoadCommand<'data, Mach: EditableMachHeader> {
    Segment(Mach::EditableSegment, Cow<'data, [Mach::EditableSection]>),
    Thread(object::macho::ThreadCommand<Mach::Endian>, Cow<'data, [u8]>),
    IdDylib(object::macho::DylibCommand<Mach::Endian>, Cow<'data, [u8]>),
    Dylib(object::macho::DylibCommand<Mach::Endian>, Cow<'data, [u8]>),
    BuildVersion(object::macho::BuildVersionCommand<Mach::Endian>, Cow<'data, [object::macho::BuildToolVersion<Mach::Endian>]>),
    Symtab(object::macho::SymtabCommand<Mach::Endian>),
    Dysymtab(object::macho::DysymtabCommand<Mach::Endian>),
    LoadDylinker(object::macho::DylinkerCommand<Mach::Endian>),
    IdDylinker(object::macho::DylinkerCommand<Mach::Endian>),
    PreboundDylib(object::macho::PreboundDylibCommand<Mach::Endian>),
    Routines32(object::macho::RoutinesCommand32<Mach::Endian>),
    SubFramework(object::macho::SubFrameworkCommand<Mach::Endian>),
    SubUmbrella(object::macho::SubUmbrellaCommand<Mach::Endian>),
    SubClient(object::macho::SubClientCommand<Mach::Endian>),
    SubLibrary(object::macho::SubLibraryCommand<Mach::Endian>),
    TwolevelHints(object::macho::TwolevelHintsCommand<Mach::Endian>),
    PrebindCksum(object::macho::PrebindCksumCommand<Mach::Endian>),
    Routines64(object::macho::RoutinesCommand64<Mach::Endian>),
    Uuid(object::macho::UuidCommand<Mach::Endian>),
    Rpath(object::macho::RpathCommand<Mach::Endian>),
    LinkeditData(object::macho::LinkeditDataCommand<Mach::Endian>),
    EncryptionInfo32(object::macho::EncryptionInfoCommand32<Mach::Endian>),
    DyldInfo(object::macho::DyldInfoCommand<Mach::Endian>),
    VersionMin(object::macho::VersionMinCommand<Mach::Endian>),
    DyldEnvironment(object::macho::DylinkerCommand<Mach::Endian>),
    EntryPoint(object::macho::EntryPointCommand<Mach::Endian>),
    SourceVersion(object::macho::SourceVersionCommand<Mach::Endian>),
    EncryptionInfo64(object::macho::EncryptionInfoCommand64<Mach::Endian>),
    LinkerOption(object::macho::LinkerOptionCommand<Mach::Endian>),
    Note(object::macho::NoteCommand<Mach::Endian>),
    FilesetEntry(object::macho::FilesetEntryCommand<Mach::Endian>),
}

fn load_command_variant_converter<'data, Mach: EditableMachHeader>(endian: Mach::Endian, data: LoadCommandData<'data, Mach::Endian>) -> MyLoadCommand<'data, Mach> {
    match data.variant().unwrap() {
        LoadCommandVariant::Segment32(_, _) => {
            let (cmd, sections_raw) = Mach::Segment::from_command(data).unwrap().unwrap();
            let (sections, tail) = object::pod::slice_from_bytes::<Mach::Section>(sections_raw, cmd.nsects(endian) as usize).unwrap();
            assert!(tail.is_empty());
            MyLoadCommand::Segment(*cmd, sections.into())
        },
        LoadCommandVariant::Segment64(_, _) => {
            let (cmd, sections_raw) = Mach::Segment::from_command(data).unwrap().unwrap();
            let (sections, tail) = object::pod::slice_from_bytes::<Mach::Section>(sections_raw, cmd.nsects(endian) as usize).unwrap();
            assert!(tail.is_empty());
            MyLoadCommand::Segment(*cmd, sections.into())
        },
        LoadCommandVariant::Thread(cmd, data) => MyLoadCommand::Thread(*cmd, data.into()),
        LoadCommandVariant::BuildVersion(cmd) => {
            let data = data.raw_data().get(size_of_val(cmd)..).unwrap_or_default();
            let (tools, tail) = object::pod::slice_from_bytes::<object::macho::BuildToolVersion<Mach::Endian>>(data, cmd.ntools.get(endian) as usize).unwrap();
            assert!(tail.is_empty());
            MyLoadCommand::BuildVersion(*cmd, tools.into())
        },
        LoadCommandVariant::IdDylib(cmd) => {
            let slice = data.raw_data().get(cmd.dylib.name.offset.get(endian) as usize..).unwrap();
            MyLoadCommand::IdDylib(*cmd, slice.into())
        },
        LoadCommandVariant::Dylib(cmd) => {
            let slice = data.raw_data().get(cmd.dylib.name.offset.get(endian) as usize..).unwrap();
            MyLoadCommand::Dylib(*cmd, slice.into())
        },
        LoadCommandVariant::Symtab(cmd) => MyLoadCommand::Symtab(*cmd),
        LoadCommandVariant::Dysymtab(cmd) => MyLoadCommand::Dysymtab(*cmd),
        LoadCommandVariant::LoadDylinker(cmd) => MyLoadCommand::LoadDylinker(*cmd),
        LoadCommandVariant::IdDylinker(cmd) => MyLoadCommand::IdDylinker(*cmd),
        LoadCommandVariant::PreboundDylib(cmd) => MyLoadCommand::PreboundDylib(*cmd),
        LoadCommandVariant::Routines32(cmd) => MyLoadCommand::Routines32(*cmd),
        LoadCommandVariant::SubFramework(cmd) => MyLoadCommand::SubFramework(*cmd),
        LoadCommandVariant::SubUmbrella(cmd) => MyLoadCommand::SubUmbrella(*cmd),
        LoadCommandVariant::SubClient(cmd) => MyLoadCommand::SubClient(*cmd),
        LoadCommandVariant::SubLibrary(cmd) => MyLoadCommand::SubLibrary(*cmd),
        LoadCommandVariant::TwolevelHints(cmd) => MyLoadCommand::TwolevelHints(*cmd),
        LoadCommandVariant::PrebindCksum(cmd) => MyLoadCommand::PrebindCksum(*cmd),
        LoadCommandVariant::Routines64(cmd) => MyLoadCommand::Routines64(*cmd),
        LoadCommandVariant::Uuid(cmd) => MyLoadCommand::Uuid(*cmd),
        LoadCommandVariant::Rpath(cmd) => MyLoadCommand::Rpath(*cmd),
        LoadCommandVariant::LinkeditData(cmd) => MyLoadCommand::LinkeditData(*cmd),
        LoadCommandVariant::EncryptionInfo32(cmd) => MyLoadCommand::EncryptionInfo32(*cmd),
        LoadCommandVariant::DyldInfo(cmd) => MyLoadCommand::DyldInfo(*cmd),
        LoadCommandVariant::VersionMin(cmd) => MyLoadCommand::VersionMin(*cmd),
        LoadCommandVariant::DyldEnvironment(cmd) => MyLoadCommand::DyldEnvironment(*cmd),
        LoadCommandVariant::EntryPoint(cmd) => MyLoadCommand::EntryPoint(*cmd),
        LoadCommandVariant::SourceVersion(cmd) => MyLoadCommand::SourceVersion(*cmd),
        LoadCommandVariant::EncryptionInfo64(cmd) => MyLoadCommand::EncryptionInfo64(*cmd),
        LoadCommandVariant::LinkerOption(cmd) => MyLoadCommand::LinkerOption(*cmd),
        LoadCommandVariant::Note(cmd) => MyLoadCommand::Note(*cmd),
        LoadCommandVariant::FilesetEntry(cmd) => MyLoadCommand::FilesetEntry(*cmd),
        _ => todo!(),
    }
}

fn size_of_slice<T>(slice: &[T]) -> usize {
    size_of::<T>() * slice.len()
}

impl<'data, Mach: EditableMachHeader> MyLoadCommand<'data, Mach> {
    fn write(&self, writable: &mut dyn WritableBuffer) -> usize {
        use MyLoadCommand::*;
        match self {
            Segment(cmd, extradata) => {
                writable.write(cmd);
                writable.write_slice(extradata);
                size_of_val(cmd) + size_of_slice(extradata)
            },
            Thread(cmd, extradata) => {
                writable.write(cmd);
                writable.write_slice(extradata);
                size_of_val(cmd) + size_of_slice(extradata)
            },
            IdDylib(cmd, extradata) => {
                writable.write(cmd);
                writable.write_slice(extradata);
                size_of_val(cmd) + size_of_slice(extradata)
            },
            Dylib(cmd, extradata) => {
                writable.write(cmd);
                writable.write_slice(extradata);
                size_of_val(cmd) + size_of_slice(extradata)
            },
            BuildVersion(cmd, extradata) => { writable.write(cmd); writable.write_slice(extradata); size_of_val(cmd) + size_of_slice(extradata) },
            Symtab(cmd) => { writable.write(cmd); size_of_val(cmd) },
            Dysymtab(cmd) => { writable.write(cmd); size_of_val(cmd) },
            LoadDylinker(cmd) => { writable.write(cmd); size_of_val(cmd) },
            IdDylinker(cmd) => { writable.write(cmd); size_of_val(cmd) },
            PreboundDylib(cmd) => { writable.write(cmd); size_of_val(cmd) },
            Routines32(cmd) => { writable.write(cmd); size_of_val(cmd) },
            SubFramework(cmd) => { writable.write(cmd); size_of_val(cmd) },
            SubUmbrella(cmd) => { writable.write(cmd); size_of_val(cmd) },
            SubClient(cmd) => { writable.write(cmd); size_of_val(cmd) },
            SubLibrary(cmd) => { writable.write(cmd); size_of_val(cmd) },
            TwolevelHints(cmd) => { writable.write(cmd); size_of_val(cmd) },
            PrebindCksum(cmd) => { writable.write(cmd); size_of_val(cmd) },
            Routines64(cmd) => { writable.write(cmd); size_of_val(cmd) },
            Uuid(cmd) => { writable.write(cmd); size_of_val(cmd) },
            Rpath(cmd) => { writable.write(cmd); size_of_val(cmd) },
            LinkeditData(cmd) => { writable.write(cmd); size_of_val(cmd) },
            EncryptionInfo32(cmd) => { writable.write(cmd); size_of_val(cmd) },
            DyldInfo(cmd) => { writable.write(cmd); size_of_val(cmd) },
            VersionMin(cmd) => { writable.write(cmd); size_of_val(cmd) },
            DyldEnvironment(cmd) => { writable.write(cmd); size_of_val(cmd) },
            EntryPoint(cmd) => { writable.write(cmd); size_of_val(cmd) },
            SourceVersion(cmd) => { writable.write(cmd); size_of_val(cmd) },
            EncryptionInfo64(cmd) => { writable.write(cmd); size_of_val(cmd) },
            LinkerOption(cmd) => { writable.write(cmd); size_of_val(cmd) },
            Note(cmd) => { writable.write(cmd); size_of_val(cmd) },
            FilesetEntry(cmd) => { writable.write(cmd); size_of_val(cmd) },
        }
    }
}

/// Rebases the file offsets in the various macho load commands (segments,
/// sections, symtab, etc...).
fn rebase_file_offsets<Mach: EditableMachHeader>(endian: Mach::Endian, commands: &mut Vec<MyLoadCommand<Mach>>, cache: &DyldCache) -> Vec<u8> {
    let mut cummulative_size = 0u64;
    let mut exports_trie_offset = 0;
    let mut exports_trie_size = 0;

    let mut old_linkedit_vmaddr = 0;
    let mut new_linkedit_file_off = 0;

    let mut symtab_offset = None;
    let mut dysymtab_offset = None;
    let mut function_starts_offset = None;
    let mut data_in_code_offset = None;
    let mut linkedit_seg_offset = None;

    // TODO: Rework with trait system.
    let mut is64 = false;

    for (idx, command) in commands.into_iter().enumerate() {
        match command {
            MyLoadCommand::Segment(seg, sections) => {
                if &seg.segname() == &b"__LINKEDIT\0\0\0\0\0\0" {
                    linkedit_seg_offset = Some(idx);
                    old_linkedit_vmaddr = seg.vmaddr(endian).into();
                    new_linkedit_file_off = cummulative_size;
                }

                seg.set_fileoff(endian, cummulative_size.try_into().unwrap());
                seg.set_filesize(endian, seg.vmsize(endian).into());

                for section in sections.to_mut() {
                    if section.offset(endian) != 0 {
                        let offset = cummulative_size + (section.addr(endian).into() - seg.vmaddr(endian).into());
                        section.set_offset(endian, offset as u32);
                    }
                }
                cummulative_size += seg.filesize(endian).into();
            },
            MyLoadCommand::DyldInfo(info) => {
                exports_trie_offset = info.export_off.get(endian);
                exports_trie_size = info.export_size.get(endian);
                info.rebase_off.set(endian, 0);
                info.rebase_size.set(endian, 0);
                info.bind_off.set(endian, 0);
                info.bind_size.set(endian, 0);
                info.weak_bind_off.set(endian, 0);
                info.weak_bind_size.set(endian, 0);
                info.lazy_bind_off.set(endian, 0);
                info.lazy_bind_size.set(endian, 0);
                info.export_off.set(endian, 0);
                info.export_size.set(endian, 0);
            },
            MyLoadCommand::LinkeditData(info) if info.cmd.get(endian) == object::macho::LC_DYLD_EXPORTS_TRIE => {
                exports_trie_offset = info.dataoff.get(endian);
                exports_trie_size = info.datasize.get(endian);
                info.dataoff.set(endian, 0);
                info.datasize.set(endian, 0);
            },
            MyLoadCommand::Symtab(_) => symtab_offset = Some(idx),
            MyLoadCommand::Dysymtab(_) => dysymtab_offset = Some(idx),
            MyLoadCommand::LinkeditData(info) if info.cmd.get(endian) == object::macho::LC_FUNCTION_STARTS =>
                function_starts_offset = Some(idx),
            MyLoadCommand::LinkeditData(info) if info.cmd.get(endian) == object::macho::LC_DATA_IN_CODE =>
                data_in_code_offset = Some(idx),
            _ => ()
        }
    }

    // TODO: Remove LC_SEGMENT_SPLIT_INFO
    let linkedit_seg_offset = match linkedit_seg_offset {
        Some(offset) => offset,
        None => {
            panic!("__LINKEDIT not found");
        }
    };
    let symtab_offset = match symtab_offset {
        Some(offset) => offset,
        None => {
            panic!("LC_SYMTAB not found");
        }
    };
    let dysymtab_offset = match dysymtab_offset {
        Some(offset) => offset,
        None => {
            panic!("LC_DYSYMTAB not found");
        }
    };
    let function_starts_offset = match function_starts_offset {
        Some(offset) => offset,
        None => {
            panic!("LC_FUNCTION_STARTS not found");
        }
    };
    let data_in_code_offset = match data_in_code_offset {
        Some(offset) => offset,
        None => {
            panic!("LC_DATA_IN_CODE not found");
        }
    };

    let mut new_linkedit_data = Vec::new();
    let (old_linkedit_data, _) = cache.data_and_offset_for_address(old_linkedit_vmaddr).unwrap();

    // Handle function starts. We simply copy it. It contains vm addresses (and
    // not file offsets), which will stay untouched through the rebasing.
    let function_starts = &mut commands[function_starts_offset];
    let function_starts = match function_starts {
        MyLoadCommand::LinkeditData(info) => info,
        _ => unreachable!(),
    };
    let function_starts_data = old_linkedit_data.get(function_starts.dataoff.get(endian) as usize..(function_starts.dataoff.get(endian) + function_starts.datasize.get(endian)) as usize).unwrap();
    function_starts.dataoff.set(endian, new_linkedit_file_off as u32 + new_linkedit_data.len() as u32);
    new_linkedit_data.extend(function_starts_data);

    // Next, handle the data_in_code. Similar to function_starts, we just need
    // to copy it.
    let data_in_code = &mut commands[data_in_code_offset];
    let data_in_code = match data_in_code {
        MyLoadCommand::LinkeditData(info) => info,
        _ => unreachable!(),
    };
    let data_in_code_data = old_linkedit_data.get(data_in_code.dataoff.get(endian) as usize..(data_in_code.dataoff.get(endian) + data_in_code.datasize.get(endian)) as usize).unwrap();
    data_in_code.dataoff.set(endian, new_linkedit_file_off as u32 + new_linkedit_data.len() as u32);
    new_linkedit_data.extend(data_in_code_data);

    // The symtab. We want to move our symbols to our linkedit data
    // segment.
    let symtab = &mut commands[symtab_offset];
    let symtab = match symtab {
        MyLoadCommand::Symtab(symtab) => symtab,
        _ => unreachable!(),
    };

    // Write symtbl
    let mut symbols = old_linkedit_data.read_slice_at::<Mach::EditableNlist>(symtab.symoff.get(endian) as u64, symtab.nsyms.get(endian) as usize).unwrap().to_vec();

    // Get original strtbl
    let strstartidx = symtab.stroff.get(endian) as u64;
    let strendidx = strstartidx + symtab.strsize.get(endian) as u64;
    let oldstrtbl = object::read::StringTable::new(old_linkedit_data, strstartidx, strendidx);

    let strtbl_start = new_linkedit_data.len();

    // Write only the required strs in the strtbl
    // Symbol table has to start with a 0, as an `n_strx` value of 0
    // signifies the end of the symbol table.
    new_linkedit_data.push(0);
    for symbol in &mut symbols {
        let symstr = oldstrtbl.get(symbol.n_strx(endian)).unwrap();
        let str_idx = new_linkedit_data.len() - strtbl_start;
        new_linkedit_data.extend(symstr);
        new_linkedit_data.push(0);
        symbol.set_n_strx(endian, str_idx as u32);
    }

    // Align symtbl.
    let cursize = new_linkedit_data.len();
    let aligned_size = (cursize + align_of::<Mach::EditableNlist>() - 1) & !align_of::<Mach::EditableNlist>();
    new_linkedit_data.resize(aligned_size, 0);

    // Write symtbl
    let symtbl_start = new_linkedit_data.len();
    println!("{}", new_linkedit_data.len());
    println!("{} {:?}", symbols.len(), symbols);
    new_linkedit_data.write_pod_slice(&symbols);
    println!("{}", new_linkedit_data.len());

    // Fixup symtab offsets
    symtab.stroff.set(endian, (new_linkedit_file_off + strtbl_start as u64) as u32);
    symtab.strsize.set(endian, (symtbl_start - strtbl_start) as u32);
    symtab.symoff.set(endian, (new_linkedit_file_off + symtbl_start as u64) as u32);

    // Next up, the dysymtab. Mostly the same shit as the symtab.
    let dysymtab = &mut commands[dysymtab_offset];
    let dysymtab = match dysymtab {
        MyLoadCommand::Dysymtab(dysymtab) => dysymtab,
        _ => unreachable!(),
    };

    // TODO: Rebase instead.
    dysymtab.indirectsymoff.set(endian, 0);
    dysymtab.nindirectsyms.set(endian, 0);

    match &mut commands[linkedit_seg_offset] {
        MyLoadCommand::Segment(seg, _) => {
            seg.set_vmsize(endian, new_linkedit_data.len().try_into().unwrap());
            seg.set_filesize(endian, new_linkedit_data.len() as u64);
        },
        _ => unreachable!(),
    }
    new_linkedit_data
}

fn handle_file<Mach: EditableMachHeader>(stream: &mut dyn WritableBuffer, cache: &DyldCache, image: DyldCacheImage) {
    let (data, header_offset) = image.image_data_and_offset().unwrap();
    let header = Mach::parse(data, header_offset).unwrap();

    let mut cur_offset = 0;
    stream.write(header);
    cur_offset += size_of_val(header);

    let endian = header.endian().unwrap();
    let mut commands_iter = header.load_commands(endian, data, header_offset).unwrap();

    let mut commands: Vec<MyLoadCommand<Mach>> = Vec::new();
    let mut segments: Vec<(usize, &[u8], u64)> = Vec::new();
    while let Some(command) = commands_iter.next().unwrap() {
        //println!("{:?}", command);
        //println!("{:?}", command.variant());
        commands.push(load_command_variant_converter(endian, command));
        let idx = commands.len() - 1;

        // Store segments and their original offsets somewhere.
        match &commands[idx] {
            MyLoadCommand::Segment(seg, _) => {
                let (data, offset) = cache.data_and_offset_for_address(seg.vmaddr(endian).into()).unwrap();
                segments.push((idx, data, offset))
            }
            _ => (),
        }
    }

    let new_linkedit_data = rebase_file_offsets(endian, &mut commands, cache);

    for command in &commands {
        let written = command.write(stream);
        cur_offset += written;
        println!("{:x} {:?}", written, command);
        //assert_eq!(written, command.cmdlen());
    }

    // Write the data for each segment.
    for (idx, (command_idx, data, segment_offset)) in segments.iter().enumerate() {
        let command = &commands[*command_idx];
        let filesize = match command {
            MyLoadCommand::Segment(seg, _) => seg.filesize(endian).into(),
            _ => unreachable!(),
        };

        let mut start_idx = *segment_offset as usize;
        let end_idx = start_idx + filesize as usize;

        if idx == 0 {
            println!("Skiping {} bytes of header for __TEXT", cur_offset);
            // Skip the header for the __TEXT segment.
            start_idx += cur_offset;
        }

        if idx == segments.len() - 1 {
            // Write linkedit from the one generated by rebase_file_offsets.
            stream.write_slice(&new_linkedit_data);
        } else {
            let segment_data = data.get(start_idx..end_idx).unwrap();
            stream.write_slice(segment_data);
        }
    }
}

// If the file is a dyld shared cache, and we're on macOS 12 or later,
// then there will be one or more "subcache" files next to this file,
// with the names filename.1, filename.2, ..., filename.symbols.
fn open_subcaches_if_exist(path: &Path) -> Vec<fs::File> {
    let mut files = Vec::new();
    for i in 1.. {
        let mut subcache_path = path.as_os_str().to_os_string();
        subcache_path.push(format!(".{}", i));
        match fs::File::open(&subcache_path) {
            Ok(subcache_file) => files.push(subcache_file),
            Err(_) => break,
        };
    }
    let mut symbols_subcache_path = path.as_os_str().to_os_string();
    symbols_subcache_path.push(".symbols");
    if let Ok(subcache_file) = fs::File::open(&symbols_subcache_path) {
        files.push(subcache_file);
    };
    println!("Found {} subcache files", files.len());
    files
}
