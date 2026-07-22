// SPDX-License-Identifier: MIT
// Copyright (c) 2026 netscope contributors
//! The operations carried inside ONC RPC — NFS and the services around it.
//!
//! Knowing a packet is "an NFS call" says very little. Whether it is a LOOKUP,
//! a READ or a WRITE is the whole question: a directory listing that turns into
//! thousands of LOOKUPs is a different performance problem from one large READ,
//! and a burst of WRITEs and COMMITs is a different one again.
//!
//! Reached from the RPC dissector, which reads the program, version and
//! procedure numbers out of the call header and hands them here.

use crate::models::Protocol;

/// ONC RPC program numbers worth naming.
pub(crate) const PROG_PORTMAP: u32 = 100_000;
pub(crate) const PROG_NFS: u32 = 100_003;
pub(crate) const PROG_MOUNT: u32 = 100_005;
pub(crate) const PROG_NLM: u32 = 100_021;
pub(crate) const PROG_STATUS: u32 = 100_024;
pub(crate) const PROG_NFS_ACL: u32 = 100_227;
pub(crate) const PROG_NFS4_CALLBACK: u32 = 0x4000_0000;
/// GlusterFS reuses the ONC RPC framing with its own program numbers.
pub(crate) const PROG_GLUSTERFS: u32 = 1_298_437;
pub(crate) const PROG_GLUSTER_HANDSHAKE: u32 = 14_398_633;

/// NFS version 3 procedures (RFC 1813 §3). Version 2 shares the low numbers
/// but diverges above them, so the version is reported alongside.
fn nfs3_procedure(proc_num: u32) -> Option<&'static str> {
    Some(match proc_num {
        0 => "NULL",
        1 => "GETATTR",
        2 => "SETATTR",
        3 => "LOOKUP",
        4 => "ACCESS",
        5 => "READLINK",
        6 => "READ",
        7 => "WRITE",
        8 => "CREATE",
        9 => "MKDIR",
        10 => "SYMLINK",
        11 => "MKNOD",
        12 => "REMOVE",
        13 => "RMDIR",
        14 => "RENAME",
        15 => "LINK",
        16 => "READDIR",
        17 => "READDIRPLUS",
        18 => "FSSTAT",
        19 => "FSINFO",
        20 => "PATHCONF",
        21 => "COMMIT",
        _ => return None,
    })
}

/// NFS version 4 collapsed almost everything into one procedure: a COMPOUND
/// that carries a list of operations, so the procedure number alone says less
/// than it does for version 3 (RFC 7530 §16).
fn nfs4_procedure(proc_num: u32) -> Option<&'static str> {
    Some(match proc_num {
        0 => "NULL",
        1 => "COMPOUND",
        _ => return None,
    })
}

/// Mount protocol procedures (RFC 1813 appendix I).
fn mount_procedure(proc_num: u32) -> Option<&'static str> {
    Some(match proc_num {
        0 => "NULL",
        1 => "MNT (mount a share)",
        2 => "DUMP",
        3 => "UMNT (unmount)",
        4 => "UMNTALL",
        5 => "EXPORT (list shares)",
        _ => return None,
    })
}

/// Portmap procedures (RFC 1833 §3).
fn portmap_procedure(proc_num: u32) -> Option<&'static str> {
    Some(match proc_num {
        0 => "NULL",
        1 => "SET",
        2 => "UNSET",
        3 => "GETPORT (where is a service?)",
        4 => "DUMP (list services)",
        5 => "CALLIT",
        _ => return None,
    })
}

/// Network Lock Manager procedures (RFC 1813 appendix II).
fn nlm_procedure(proc_num: u32) -> Option<&'static str> {
    Some(match proc_num {
        0 => "NULL",
        1 => "TEST",
        2 => "LOCK",
        3 => "CANCEL",
        4 => "UNLOCK",
        5 => "GRANTED",
        _ => return None,
    })
}

/// The protocol a program number belongs to, and a name for the procedure.
///
/// Returns `None` for programs with no dedicated protocol, so the caller keeps
/// the generic RPC label.
pub(crate) fn describe(program: u32, version: u32, proc_num: u32) -> Option<(Protocol, String)> {
    let (protocol, family, name) = match program {
        PROG_NFS => {
            if version >= 4 && (45..=51).contains(&proc_num) {
                let res = super::pnfs::dissect_pnfs(None, None, 0, 0, proc_num, &[]);
                return Some((res.protocol, res.summary));
            }
            let name = if version >= 4 {
                nfs4_procedure(proc_num)
            } else {
                nfs3_procedure(proc_num)
            };
            (Protocol::Nfs, "NFS", name)
        }
        PROG_MOUNT => (Protocol::Nfs, "Mount", mount_procedure(proc_num)),
        PROG_NLM => (Protocol::Nfs, "NLM", nlm_procedure(proc_num)),
        PROG_NFS_ACL => (Protocol::Nfs, "NFS ACL", None),
        PROG_NFS4_CALLBACK => (Protocol::NfsCb, "NFSv4 Callback", None),
        PROG_STATUS => (Protocol::Nfs, "NSM (status monitor)", None),
        PROG_PORTMAP => (Protocol::Rpc, "Portmap", portmap_procedure(proc_num)),
        PROG_GLUSTERFS => (Protocol::GlusterFs, "GlusterFS", None),
        PROG_GLUSTER_HANDSHAKE => (Protocol::GlusterFs, "GlusterFS handshake", None),
        _ => return None,
    };
    let summary = match name {
        Some(op) => format!("{family} v{version} {op}"),
        None => format!("{family} v{version} procedure {proc_num}"),
    };
    Some((protocol, summary))
}

// This module has no `dissect_*` entry point of its own. The RPC dissector
// calls [`describe`] and builds the result, because RPC is what holds the
// addresses and ports. A second entry point here would be a code path nothing
// calls, free to drift out of step with the one that runs.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfs_v3_operations_are_named() {
        assert_eq!(describe(PROG_NFS, 3, 6).unwrap().1, "NFS v3 READ");
        assert_eq!(describe(PROG_NFS, 3, 7).unwrap().1, "NFS v3 WRITE");
        assert_eq!(describe(PROG_NFS, 3, 3).unwrap().1, "NFS v3 LOOKUP");
    }

    /// Distinguishing these is the point: a directory walk that becomes
    /// thousands of LOOKUPs is a different problem from one big READ.
    #[test]
    fn directory_operations_are_distinguishable() {
        assert_eq!(describe(PROG_NFS, 3, 16).unwrap().1, "NFS v3 READDIR");
        assert_eq!(describe(PROG_NFS, 3, 17).unwrap().1, "NFS v3 READDIRPLUS");
        assert_eq!(describe(PROG_NFS, 3, 21).unwrap().1, "NFS v3 COMMIT");
    }

    /// Version 4 folded almost everything into COMPOUND, so the same procedure
    /// number means something different there.
    #[test]
    fn version_four_uses_its_own_procedure_list() {
        assert_eq!(describe(PROG_NFS, 4, 1).unwrap().1, "NFS v4 COMPOUND");
        // Procedure 6 is READ in v3 but undefined in v4's short list.
        assert_eq!(describe(PROG_NFS, 4, 6).unwrap().1, "NFS v4 procedure 6");
        assert_eq!(describe(PROG_NFS, 3, 6).unwrap().1, "NFS v3 READ");
    }

    #[test]
    fn mount_and_portmap_are_named() {
        assert_eq!(
            describe(PROG_MOUNT, 3, 1).unwrap().1,
            "Mount v3 MNT (mount a share)"
        );
        assert_eq!(
            describe(PROG_PORTMAP, 2, 3).unwrap().1,
            "Portmap v2 GETPORT (where is a service?)"
        );
    }

    /// Portmap stays labelled RPC because that is the protocol it is; the
    /// filesystem programs get their own label.
    #[test]
    fn programs_map_to_the_right_protocol() {
        assert_eq!(describe(PROG_NFS, 3, 6).unwrap().0, Protocol::Nfs);
        assert_eq!(describe(PROG_MOUNT, 3, 1).unwrap().0, Protocol::Nfs);
        assert_eq!(describe(PROG_PORTMAP, 2, 3).unwrap().0, Protocol::Rpc);
        assert_eq!(
            describe(PROG_GLUSTERFS, 330, 1).unwrap().0,
            Protocol::GlusterFs
        );
    }

    /// An unknown program yields nothing, which is how RPC learns to keep its
    /// own generic label rather than having one guessed for it.
    #[test]
    fn unknown_program_is_not_claimed() {
        assert!(describe(999_999, 1, 1).is_none());
    }

    /// A procedure we do not have a name for still reports its number, which is
    /// how NFS operations are referred to anyway.
    #[test]
    fn unknown_procedure_reports_its_number() {
        assert_eq!(describe(PROG_NFS, 3, 99).unwrap().1, "NFS v3 procedure 99");
    }
}
