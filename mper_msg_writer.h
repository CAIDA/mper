/*
** Routines to create client/server messages to send on the control socket.
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

#ifndef __MPER_MSG_WRITER_H__
#define __MPER_MSG_WRITER_H__

/*
** Creates a message from the provided control word array of {length}
** elements, and returns a pointer to the created message of
** {*msg_length_out} bytes.  The returned message is stored in statically
** allocated memory, and thus the user should make a copy if the contents
** are needed persistently.
**
** The {words} argument is intentionally declared with a type
** compatible with parse_control_message().  However, when creating a
** message, not all fields need to be filled in by the user.  In
** particular, the cw_name and cw_type fields need not be filled in.
**
** On error, this sets {*msg_length_out} to 0 and returns the error
** message.  (Note: This function never returns NULL.)
*/
const char *
create_control_message(control_word_t *words, size_t length,
		       size_t *msg_length_out);

/*
** Creates a message from the provided control word array of {length}
** elements, and returns a pointer to the created message of
** {*msg_length_out} bytes.  The returned message is stored in statically
** allocated memory, and thus the user should make a copy if the contents
** are needed persistently.
**
** Unlike for create_control_message(), this function requires the control
** word array to be fully filled in.  This function is mainly provided for
** debugging and testing purposes.
**
** On error, this sets {*msg_length_out} to 0 and returns the error
** message.  (Note: This function never returns NULL.)
*/
const char *
marshal_control_message(const control_word_t *words, size_t length,
			size_t *msg_length_out);

#endif /* __MPER_MSG_WRITER_H__ */
