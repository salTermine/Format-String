# Format String Exploit

	Implement an attack that uses only the format string vulnerability. Your goal 
	is to execute arbitrary code injected by the attacker. (Your code can simply 
	call ownme().) Follow the strategy given in your homework solution.

	For this attack, do not overwrite the canary — you should target and modify the 
	return address without changing any other value on the stack.