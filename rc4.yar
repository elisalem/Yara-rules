rule custom_rc4
{

meta:
	author = "Eli Salem"
	description = "Simple YARA rule to detect custom RC4 encryption"
	
strings:
	$a = {81 7D FC 00 01 00 00}
	$b = {3D 00 01 00 00}
	$c = {81 FB 00 01 00 00}
	$d = {81 FF 00 01 00 00}
	
condition:
	($a or $d or $b or $c)
	
}