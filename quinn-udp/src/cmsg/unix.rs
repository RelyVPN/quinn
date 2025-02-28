use std::ffi::{c_int, c_uchar};

use super::{CMsgHdr, MsgHdr};

#[derive(Copy, Clone)]
#[repr(align(8))] // Conservative bound for align_of<libc::cmsghdr>
pub(crate) struct Aligned<T>(pub(crate) T);

/// Helpers for [`libc::msghdr`]
impl MsgHdr for libc::msghdr {
    type ControlMessage = libc::cmsghdr;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage {
        unsafe { libc::CMSG_FIRSTHDR(self) }
    }

    fn cmsg_nxt_hdr(&self, cmsg: &Self::ControlMessage) -> *mut Self::ControlMessage {
        let next = unsafe { libc::CMSG_NXTHDR(self, cmsg) };
        
        // 在macOS上添加额外检查，防止无效的控制消息导致无限循环
        // 注意：这个bug在macOS各个版本中都存在，包括macOS 15.3.1 (Sonoma)
        #[cfg(apple)]
        if unsafe { next.as_ref() }
            .is_some_and(|n| (n.cmsg_len as usize) < std::mem::size_of::<libc::cmsghdr>())
        {
            // 静默修复，不再输出警告日志
            return std::ptr::null_mut();
        }
        
        next
    }

    fn set_control_len(&mut self, len: usize) {
        self.msg_controllen = len as _;
        if len == 0 {
            // netbsd is particular about this being a NULL pointer if there are no control
            // messages.
            self.msg_control = std::ptr::null_mut();
        }
    }

    fn control_len(&self) -> usize {
        self.msg_controllen as _
    }
}

#[cfg(apple_fast)]
impl MsgHdr for crate::imp::msghdr_x {
    type ControlMessage = libc::cmsghdr;

    fn cmsg_first_hdr(&self) -> *mut Self::ControlMessage {
        let selfp = self as *const _ as *mut libc::msghdr;
        unsafe { libc::CMSG_FIRSTHDR(selfp) }
    }

    fn cmsg_nxt_hdr(&self, cmsg: &Self::ControlMessage) -> *mut Self::ControlMessage {
        let selfp = self as *const _ as *mut libc::msghdr;
        let next = unsafe { libc::CMSG_NXTHDR(selfp, cmsg) };

        // macOS的CMSG_NXTHDR可能会持续返回一个无效的cmsg。
        // 这个bug在各个macOS版本中都存在，包括macOS 15.3.1 (Sonoma)
        // 在这种情况下，返回null指针，表示控制消息链的结束。
        if unsafe { next.as_ref() }
            .is_some_and(|n| (n.cmsg_len as usize) < std::mem::size_of::<libc::cmsghdr>())
        {
            // 静默修复，不再输出警告日志
            return std::ptr::null_mut();
        }

        next
    }

    fn set_control_len(&mut self, len: usize) {
        self.msg_controllen = len as _;
    }

    fn control_len(&self) -> usize {
        self.msg_controllen as _
    }
}

/// Helpers for [`libc::cmsghdr`]
impl CMsgHdr for libc::cmsghdr {
    fn cmsg_len(length: usize) -> usize {
        unsafe { libc::CMSG_LEN(length as _) as usize }
    }

    fn cmsg_space(length: usize) -> usize {
        unsafe { libc::CMSG_SPACE(length as _) as usize }
    }

    fn cmsg_data(&self) -> *mut c_uchar {
        unsafe { libc::CMSG_DATA(self) }
    }

    fn set(&mut self, level: c_int, ty: c_int, len: usize) {
        self.cmsg_level = level as _;
        self.cmsg_type = ty as _;
        self.cmsg_len = len as _;
    }

    fn len(&self) -> usize {
        self.cmsg_len as _
    }
}
