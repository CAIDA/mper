/*
** Routines to parse client/server messages received on the control socket.
**
** --------------------------------------------------------------------------
** Author: Young Hyun
** Copyright (C) 2009 The Regents of the University of California.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
** 
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** 
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __MPER_MSG_READER_H__
#define __MPER_MSG_READER_H__

/*
** Parses a control message and returns a pointer to {*length_out} number of
** control word structures.
**
** On parse error, this sets {*length_out} to 0 and
**  (1) stores the reqnum in the cw_uint field of the first control word
**      (if cw_code of the first control word does not equal KC_REQNUM,
**       then even the reqnum couldn't be parsed and cw_uint will be 0), and
**  (2) stores the error message in the cw_str field of the second control
**      word structure (cw_code will equal KC_ERROR).
**
** (Note: This function never returns NULL.)
*/
const control_word_t *
parse_control_message(const char *message, size_t *length_out);

/* Prints out control word structures to stderr. */
void dump_parsed_message(const control_word_t *control_words, size_t length);

#endif /* __MPER_MSG_READER_H__ */
