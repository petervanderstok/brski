/* TEST of BRSKI -- implementation of pledge
 * separation with pledge.c to allow separate test main
 *
 * Copyright (C) 2010--2018 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 *
 */
 
#include "pledge.h" 
 
int
main(int argc, char **argv) {
	pledge(argc, argv);
}
