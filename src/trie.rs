use std::error::Error;
use std::marker::PhantomData;

use object::macho::*;
use custom_debug::Debug;

enum TrieDecodeError {
    Leb128Error(nano_leb128::LEB128DecodeError),
    UnexpectedEof,
}

impl From<nano_leb128::LEB128DecodeError> for TrieDecodeError {
    fn from(error: nano_leb128::LEB128DecodeError) -> TrieDecodeError {
        TrieDecodeError::Leb128Error(error)
    }
}

pub struct Trie<'data, T> {
    data: &'data [u8],
    phantom: PhantomData<T>
}

impl<'data, T> Trie<'data, T> {
    pub fn from_bytes(data: &'data [u8]) -> Trie<'data, T> {
        Trie { data, phantom: PhantomData }
    }
    pub fn iter(&self) -> TrieIter<'data, T> {
        TrieIter {
            data: self.data,
            stack: Vec::new(),
            first_call: true,
            phantom: PhantomData,
        }
    }
}

struct TrieIter<'data, T> {
    data: &'data [u8],
    stack: Vec<TrieIterStack<'data>>,
    first_call: bool,
    phantom: PhantomData<T>
}

struct TrieIterStack<'data> {
    str_component: &'data [u8],
    num_children_left: u64,
    offset: usize,
}

impl<'data, T: TrieData<'data> + 'data> TrieIter<'data, T>
{
    fn parse_stack_beginning(&mut self, offset: usize, str_component: &'data [u8]) -> Result<Option<TrieItem<T>>, TrieDecodeError> {
        let (terminal_size, len) = nano_leb128::ULEB128::read_from(self.data.get(offset..).ok_or(TrieDecodeError::UnexpectedEof)?)?;
        let terminal_size = u64::from(terminal_size);
        let node_information_offset = len;
        let children_offset = node_information_offset + terminal_size as usize;
        let num_children = self.data.get(children_offset).ok_or(TrieDecodeError::UnexpectedEof)?;
        self.stack.push(TrieIterStack {
            str_component,
            num_children_left: u64::from(*num_children),
            offset: children_offset + 1,
        });

        if terminal_size != 0 {
            let terminal_data = self.data.get(node_information_offset..node_information_offset + terminal_size as usize).ok_or(TrieDecodeError::UnexpectedEof)?;
            let val = T::from_bytes(terminal_data)?;
            Ok(Some(TrieItem {
                name: Vec::new(),
                data: val,
            }))
        } else {
            Ok(None)
        }
    }
    fn raw_next(&mut self) -> Result<Option<TrieItem<T>>, TrieDecodeError> {
        // Special case first element because otherwise everything is painful.
        if self.first_call {
            self.first_call = false;
            if let Some(v) = self.parse_stack_beginning(0, &[])? {
                return Ok(Some(v))
            }
        }

        while !self.stack.is_empty() {
            if self.stack.last().unwrap().num_children_left == 0 {
                self.stack.pop();
            } else {
                let stack_item = self.stack.last_mut().unwrap();
                let s_len = self.data.get(stack_item.offset..).ok_or(TrieDecodeError::UnexpectedEof)?.iter().position(|v| *v == 0).ok_or(TrieDecodeError::UnexpectedEof)?;
                let new_prefix_part = self.data.get(stack_item.offset..stack_item.offset + s_len).ok_or(TrieDecodeError::UnexpectedEof)?;
                stack_item.offset += s_len + 1;

                let (child_node_offset, len) = nano_leb128::ULEB128::read_from(&self.data[stack_item.offset..])?;
                let child_node_offset = u64::from(child_node_offset);

                stack_item.offset += len;
                stack_item.num_children_left -= 1;

                if let Some(v) = self.parse_stack_beginning(child_node_offset as usize, new_prefix_part)? {
                    return Ok(Some(v))
                }
            }
        }

        Ok(None)
    }
}

trait TrieData<'data> {
    fn from_bytes(data: &'data [u8]) -> Result<Self, TrieDecodeError> where Self: 'data + Sized;
}

pub struct ExportInfo<'data> {
    pub address: u64,
    pub flags: u64,
    pub other: u64,
    pub import_name: &'data [u8],
}

impl<'data> TrieData<'data> for ExportInfo<'data> {
    fn from_bytes(mut data: &'data [u8]) -> Result<ExportInfo<'data>, TrieDecodeError> {
        let (flags, len) = nano_leb128::ULEB128::read_from(data)?;
        data = &data[len..];
        let flags = u64::from(flags);

        let (address, other, import_name) = if flags & u64::from(EXPORT_SYMBOL_FLAGS_REEXPORT) != 0 {
            let (other, len) = nano_leb128::ULEB128::read_from(data)?;
            data = &data[len..];
            (0, u64::from(other), data)
        } else {
            let (address, len) = nano_leb128::ULEB128::read_from(data)?;
            data = &data[len..];
            let address = u64::from(address);

            let other = if flags & u64::from(EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0 {
                let (other, len) = nano_leb128::ULEB128::read_from(data)?;
                data = &data[len..];
                u64::from(other)
            } else { 0 };

            (address, other, &[][..])
        };

        Ok(ExportInfo {
            address, other, flags, import_name
        })
    }
}

impl<'data, T: TrieData<'data> + 'data> Iterator for TrieIter<'data, T> {
    type Item = TrieItem<T>;
    fn next(&mut self) -> Option<TrieItem<T>> {
        self.raw_next().ok().flatten()
    }
}

#[derive(Debug)]
pub struct TrieItem<T> {
    #[debug(with = "str_fmt")]
    name: Vec<u8>,
    data: T
}

fn str_fmt(n: &Vec<u8>, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    write!(f, "{:?}", String::from_utf8_lossy(n))
}
