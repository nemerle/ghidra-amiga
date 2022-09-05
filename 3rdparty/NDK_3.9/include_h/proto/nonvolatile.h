#ifndef PROTO_NONVOLATILE_H
#define PROTO_NONVOLATILE_H

/*
**	$VER: nonvolatile.h 44.1 (1.11.1999)
**	Includes Release 45.1
**
**	Lattice `C' style prototype/pragma header file combo
**
**	(C) Copyright 2001 Amiga, Inc.
**	    All Rights Reserved
*/

#ifndef PRAGMAS_NONVOLATILE_PRAGMAS_H
#include <pragmas/nonvolatile_pragmas.h>
#endif

#ifndef EXEC_LIBRARIES_H
#include <exec/libraries.h>
#endif

#ifndef __NOLIBBASE__
extern struct Library * NVBase;
#endif /* __NOLIBBASE__ */

#endif /* PROTO_NONVOLATILE_H */
