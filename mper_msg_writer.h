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
** The following macros are useful for filling out a control_word_t array
** to pass to create_control_message().
**
** Use:
**   1. Declare a control_word_t array somewhere, say in the variable {words}.
**
**   2. Call INIT_CMESSAGE to initialize the message.  For example,
**
**         INIT_CMESSAGE(words, 1234, PING);
**
**      Note: The command code should not have the 'KC_' prefix or the
**            '_CMD' suffix.  This is for increased readability.
**            So use 'PING' instead of 'KC_PING_CMD' in the third argument.
**
**   3. Call zero or more of the SET_xxx_CWORD macros to fill in any options.
**      For example,
**
**         SET_UINT_CWORD(words, 1, TTL, 5);
**         SET_STR_CWORD(words, 2, TXT, "Hello, World!", 13);
**
**
**      Notes: (i) The SET_xxx_CWORD macros take the ordinal _position_ of
**                 the option.  The first option has position 1, the second
**                 option position 2, etc.  This position is different from
**                 the index the option would have in the control_word_t
**                 array.  The ordinal position is easier to specify
**                 correctly than the underlying array index.
**
**            (ii) The option code should not have the 'KC_' prefix or
**                 the '_OPT' suffix.  This is for increased readability.
**                 So use 'TTL' instead of 'KC_TTL_OPT' in the third argument.
**
**   4. Use the CMESSAGE_LEN macro to calculate the corrent length value to
**      pass to create_control_message() and marshal_control_message().
**      If you are creating a command with {n} options, then CMESSAGE_LEN(n)
**      equals the length of the underlying control_word_t array.
**      
**      For example, here are the steps to create a message with two options:
**
**         control_word_t words[MPER_MSG_MAX_WORDS];
**
**         INIT_CMESSAGE(words, 1234, PING);
**         SET_UINT_CWORD(words, 1, TTL, 5);
**         SET_STR_CWORD(words, 2, TXT, "Hello, World!", 13);
**
**         msg = create_control_message(words, CMESSAGE_LEN(2), &msg_length);
*/

#define CMESSAGE_LEN(n) (n)+2

#define INIT_CMESSAGE(words,reqnum,cmd) \
  memset(words, 0, 2 * sizeof(control_word_t)); \
  (words)[0].cw_code = KC_REQNUM; \
  (words)[0].cw_uint = reqnum; \
  (words)[1].cw_code = KC_##cmd##_CMD

#define SET_UINT_CWORD(words,idx,code,value) \
  (words)[(idx)+1].cw_name = NULL; \
  (words)[(idx)+1].cw_code = KC_##code##_OPT; \
  (words)[(idx)+1].cw_type = KT_NONE; \
  (words)[(idx)+1].cw_uint = value; \
  (words)[(idx)+1].cw_len = 0

#define SET_STR_CWORD(words,idx,code,value,len)	\
  (words)[(idx)+1].cw_name = NULL; \
  (words)[(idx)+1].cw_code = KC_##code##_OPT; \
  (words)[(idx)+1].cw_type = KT_NONE; \
  (words)[(idx)+1].cw_str = value; \
  (words)[(idx)+1].cw_len = len

#define SET_BLOB_CWORD(words,idx,code,value,len) \
  (words)[(idx)+1].cw_name = NULL; \
  (words)[(idx)+1].cw_code = KC_##code##_OPT; \
  (words)[(idx)+1].cw_type = KT_NONE; \
  (words)[(idx)+1].cw_blob = value; \
  (words)[(idx)+1].cw_len = len

#define SET_SYMBOL_CWORD(words,idx,code,value) \
  (words)[(idx)+1].cw_name = NULL; \
  (words)[(idx)+1].cw_code = KC_##code##_OPT; \
  (words)[(idx)+1].cw_type = KT_NONE; \
  (words)[(idx)+1].cw_symbol = value; \
  (words)[(idx)+1].cw_len = 0

#define SET_ADDRESS_CWORD(words,idx,code,value) \
  (words)[(idx)+1].cw_name = NULL; \
  (words)[(idx)+1].cw_code = KC_##code##_OPT; \
  (words)[(idx)+1].cw_type = KT_NONE; \
  (words)[(idx)+1].cw_address = value; \
  (words)[(idx)+1].cw_len = 0

#define SET_PREFIX_CWORD(words,idx,code,value) \
  (words)[(idx)+1].cw_name = NULL; \
  (words)[(idx)+1].cw_code = KC_##code##_OPT; \
  (words)[(idx)+1].cw_type = KT_NONE; \
  (words)[(idx)+1].cw_prefix = value; \
  (words)[(idx)+1].cw_len = 0

#define SET_TIMEVAL_CWORD(words,idx,code,tvp) \
  (words)[(idx)+1].cw_name = NULL; \
  (words)[(idx)+1].cw_code = KC_##code##_OPT; \
  (words)[(idx)+1].cw_type = KT_NONE; \
  (words)[(idx)+1].cw_timeval.tv_sec = (tvp)->tv_sec; \
  (words)[(idx)+1].cw_timeval.tv_usec = (tvp)->tv_usec;	\
  (words)[(idx)+1].cw_len = 0

#define SET_TIMEVAL2_CWORD(words,idx,code,sec,usec) \
  (words)[(idx)+1].cw_name = NULL; \
  (words)[(idx)+1].cw_code = KC_##code##_OPT; \
  (words)[(idx)+1].cw_type = KT_NONE; \
  (words)[(idx)+1].cw_timeval.tv_sec = sec; \
  (words)[(idx)+1].cw_timeval.tv_usec = usec; \
  (words)[(idx)+1].cw_len = 0


/* ====================================================================== */

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
