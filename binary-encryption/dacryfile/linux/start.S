.code32
.section .data

.section .bss

.section .text
.globl _vx_start
_vx_start:

	pushl %edx	

	call	vx_main	/* we call the main vx program */

	/* 
	 * really should be a:
	 *
	 * test	%eax, %eax
	 * jnz	exit_failure
	 *
	 */

	popl %edx	/* restore at_exit pointer */

	movl $entry, %ecx
	jmpl 	*%ecx
