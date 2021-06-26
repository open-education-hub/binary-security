#!/usr/bin/awk -f


BEGIN {
	FS="[(), {}]+"
	count = 0
	morse[".-"] = "a";
	morse["-..."] = "b";
	morse["-.-."] = "c";
	morse["-.."] = "d";
	morse["."] = "e";
	morse["..-."] = "f";
	morse["--."] = "g";
	morse["...."] = "h";
	morse[".."] = "i";
	morse[".---"] = "j";
	morse["-.-"] = "k";
	morse[".-.."] = "l";
	morse["--"] = "m";
	morse["-."] = "n";
	morse["---"] = "o";
	morse[".--."] = "p";
	morse["--.-"] = "q";
	morse[".-."] = "r";
	morse["..."] = "s";
	morse["-"] = "t";
	morse["..-"] = "u";
	morse["...-"] = "v";
	morse[".--"] = "w";
	morse["-..-"] = "x";
	morse["-.--"] = "y";
	morse["--.."] = "z";
	morse["-----"] = " ";
}

{
	if ($1 == "nanosleep") {
		count++;
	} else {
		if (led_off == 1 && count == 3) {
			printf "%s", morse[code]
			code = ""
		}

		if (led_off == 0) {
			if (count == 1)
				code = code "."
			else if (count == 3)
				code = code "-"
		}

		if ($3 == "KDSETLED") {
			if ($4 == 0)
				led_off = 1
			else
				led_off = 0
		}

		count = 0
	}
}

END {
	print ""
}
