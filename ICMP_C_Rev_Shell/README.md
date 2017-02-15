 icmpsh - simple icmp command shell
 Original Copyright (c) 2010, Nico Leidecker <nico@leidecker.info>

**********************************************************
*   This is amazing stuff and Nico deserves all my respect
**********************************************************

     Modified by F.Zinzloun.Bersani to a Win32 C console app. Folloows configuration in VS 2015:
	 - create a C++ Win32 Console App
	 - delete all the headers file, leave only the main cpp file
	 - copy the content of this file inside the main cpp file. Change the extension of the file in .c
	 - open the project's properties window,expand C/C++, select All options and set the following:
		-Compile as: Compile as C code/TC
		-Precompiled Headers: Not using precompiled headers
		-Runtime library to Multi-threaded/MT (will include the visual c++ runtime in the exe)
	That should be enough. Generate it
	Tested on Windows Server 2008 64bit, Windows 10 Home Edition 64 bit
