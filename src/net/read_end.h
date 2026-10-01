// SPDX-License-Identifier: GPL-3.0-or-later
// what one read after a probe ended with. these are different facts about
// the peer and must not collapse into "no answer". no winsock here, the
// unit-test build includes it.
#pragma once

enum class ReadEnd {
    Data,      // bytes arrived
    Fin,       // peer closed without sending anything
    Reset,     // peer or path sent rst
    Held,      // nothing arrived, connection still open at the deadline
    NoConnect, // tcp handshake itself failed
    Error,     // any other socket error
};

inline const char* read_end_name(ReadEnd e) {
    switch (e) {
    case ReadEnd::Data:      return "reply";
    case ReadEnd::Fin:       return "closed by peer";
    case ReadEnd::Reset:     return "reset";
    case ReadEnd::Held:      return "no reply, held open";
    case ReadEnd::NoConnect: return "no connect";
    default:                 return "socket error";
    }
}
