use warnings;
use strict;
use File::Copy;
use File::Find;

#--------------------------------------------------------------------------------------------------------
# UPD: Finally I've found much more nice solving of linking problem.
# http://hostagebrain.blogspot.com/2015/04/linking-problem-with-c.html
# so, this script now looks useless - maybe somebody will find it useful for some another tasks
#--------------------------------------------------------------------------------------------------------
# 
# Description:
#
#     my_lovely_refactor.pl - perl script for replacing lexems in c/c++ code:
#         - function names
#         - variable names
#         - object names
#         - method names
#         - field names
#         - maybe something else
# 
#     It enums all files in path_to_dir_with_sources, extracts files with extentions you need, 
#     and using heuristic detection on context replace all lexems you want to another lexems.
# 
#--------------------------------------------------------------------------------------------------------
# Usage:
# 
# fill in script:
#     - @extensions
#     - %replacer
#     - custom_data_types (optional)
# run:
#     my_lovely_refactor.pl path_to_dir_with_sources
# 
# By default it adjusted (@extensions, %replacer. custom_data_types is not used) to modify yara project
# 
#--------------------------------------------------------------------------------------------------------
# Heuristic restrictions (known problems):
#
# 1) Code as string
# It won't work in case if it's part of long string const (for example, C/C++ code into char[] const)
# for this purpose need to count quotes from the beginning of the file.
# (and even maybe unwrap defines)
# but not all quotes - only those of them, which isn't escaped & not in comments
# so, it's not trivial task and the easiest way implement it - make lexical/syntax analyzer
# 
# 2) Non-standart data types
# You need to care manually for case if it's variable with some custom data type
#		Here are '# custom_data_types' part - here are can be placed custom data types regexps.
# 
# 3) False positive detections
# I've tested this code on several projects - got rid from all problems on these projects.
# But unknown sources can have unknown problems
# 
#--------------------------------------------------------------------------------------------------------
# F.A.Q.
# 
# Q: Why you can't just replace substring?
# A: For example, I want replace lexem 'socket' to 'my_lovely_socket', and here are consturction:
#     socket = GetProcAddress(..., "socket" ,...)
#    Simple replacing of string ruin logic of your code.
# 
# Q: Why you don't use some tools for refactoring?
# A: Almost all of them - it's plugins for some IDE, or paid software, or compiler-specific stuff.
#    I wanted create set of rules for project and then just apply it to projects.
#    And I didn't want to glue to some compiler/ide.
#    I doubt plugins have such batch functional.
#    Here are one option - util named 'cscope' - it seems what I need.
#    It has creepy interface & I didn't understood how to use it. Yet.
# 
# Q: Why just don't use /FORCE linker option (or any analogue on not-microsoft linker)
#    'properties -> Linker -> General -> Force File Output' with any of next values:
#        "Enabled (/FORCE)"
#        "Multiply Defined Symbol Only (/FORCE:MULTIPLE)"
# A: Bcs it seems for me more creepy than heuristic replacing in sources. How it can resolve such
#    situation automatically - I don't know.
# 
# Q: Why just don't use defines?
# A: You can use defines. And it is the best decision.
# 
#--------------------------------------------------------------------------------------------------------
# author: hostagebrain.blogspot.com 
#--------------------------------------------------------------------------------------------------------
# options

my @extensions = (
	'c',
	'h',
	#'cpp',
);

my %replacer = (
	
	#----------------------------------------------------------------
	# redis rules
	# redis-extensions: 'c', 'cpp', 'h'
	# also redis has 2 custom_data_types entries - uncomment it
	
	#'pthread_create'		=> 'redis_internal_pthread_create',
	#'pthread_cond_init'		=> 'redis_internal_pthread_cond_init',
	#'pthread_cond_destroy'	=> 'redis_internal_pthread_cond_destroy',
	#'pthread_cond_wait'		=> 'redis_internal_pthread_cond_wait',
	#'pthread_cond_signal'	=> 'redis_internal_pthread_cond_signal',
    #
	#'socket'				=> 'redis_internal_socket',
	#'WSASend'				=> 'redis_internal_WSASend',
	#'WSARecv'				=> 'redis_internal_WSARecv',
	#'WSACleanup'			=> 'redis_internal_WSACleanup',
	#'ioctlsocket'			=> 'redis_internal_ioctlsocket',
	#'setsockopt'			=> 'redis_internal_setsockopt',
	#'getsockopt'			=> 'redis_internal_getsockopt',
	#'connect'				=> 'redis_internal_connect',
	#'listen'				=> 'redis_internal_listen',
	#'bind'					=> 'redis_internal_bind',
	#'shutdown'				=> 'redis_internal_shutdown',
	#'htons'					=> 'redis_internal_htons',
	#'htonl'					=> 'redis_internal_htonl',
	#'getpeername'			=> 'redis_internal_getpeername',
	#'getsockname'			=> 'redis_internal_getsockname',
	#'ntohs'					=> 'redis_internal_ntohs',
	#'select'				=> 'redis_internal_select',
	#'ntohl'					=> 'redis_internal_ntohl',
	#'freeaddrinfo'			=> 'redis_internal_freeaddrinfo',
	#'getaddrinfo'			=> 'redis_internal_getaddrinfo',
	#'WSASetLastError'		=> 'redis_internal_WSASetLastError',
	#'WSAGetLastError'		=> 'redis_internal_WSAGetLastError',
	#'WSAIoctl'				=> 'redis_internal_WSAIoctl',
	
	#----------------------------------------------------------------
	# yara rules
	# yara-extensions: 'c', 'h'
	
	'strlcpy' => 'libyara_internal_strlcpy',
	'strlcat' => 'libyara_internal_strlcat',
	
	#----------------------------------------------------------------
);

#---------------------------------------------------------------------------------------------------
# routines

sub give_all_child_fullpaths {
	
	my $root_dir = shift;
	
	my @give_all_result;
	
	my $process_file = sub  {
		if (-f $_){
			push @give_all_result, $_;
		}
	};
	
	find({ wanted => \&$process_file, no_chdir => 1 }, $root_dir);

	return @give_all_result;
}

sub give_nearest_free_bak_name {
	
	my $base = shift;
	my $counter = 0;
	
	while(1){
		my $result = sprintf($base.".%d.bak", $counter);
		return $result if (! -e $result);
		$counter++;
	}
	
}

sub give_me_extnsions_regex {
	
	my $result = ".*\\.(?:";
	for(my $i = 0; $i < @extensions; $i++){
		$result .= "(?:".$extensions[$i].")|";
	}
	$result = substr($result, 0, length($result)-1);
	$result .= ")\$";
	return $result;
	
}

#---------------------------------------------------------------------------------------------------
# heur context-recognizing regex

my $heur_context_pattern_template = qr/
	(
		# PREFIXES
		(?:
			# COMMON CONSTRUCTIONS:
			(?:\;)|			# ;		if it's new statement
			(?:\=)|			# =		if it returns rvalue
			(?:\.)|			# .		if it's method's name
			(?:\()|			# (		if it's parameter of a function
			(?:\))|			# )		if it's statement into if without scope
			(?:\,)|			# ,		if it's not first parameter in function calling
			(?:\{)|			# {		if it's the first statement in the scope
			(?:\:)|			# :		if it's in switch-case or ternary operator
			(?:\[)|			# (		if it's index in some array
			(?:\})|			# (		if it's the first statement after the scope
			
			# OPERATORS:
			(?:\+)|			# plus
			(?:\-)|			# minus
			(?:\*)|			# multiply
			(?:\/)|			# div
			(?:\%)|			# modulus div
			
			(?:\+\+)|		# increment
			(?:\-\-)|		# decrement
			
			(?:==)|			# equal
			(?:!=)|			# not equal
			(?:>)|			# more
			(?:>=)|			# more or equal
			(?:<)|			# less
			(?:<=)|			# less or equal
			
			(?:\&\&)|		# and
			(?:\!\!)|		# or
			(?:\!)|			# not

			(?:\&)|			# bitwise and
			(?:\|)|			# bitwise or
			(?:\^)|			# bitwise xor
			(?:\~)|			# bitwise not
			(?:<<)|			# shift left
			(?:>>)|			# shift right

			(?:\+\=)|		# +=
			(?:\-\=)|		# -=
			(?:\*\=)|		# *=
			(?:\/\=)|		# 
			(?:\%\=)|		# %=
			(?:\<\<\=)|		# <<=
			(?:\>\>\=)|		# >>=
			(?:\&\=)|		# &=
			(?:\^\=)|		# ^=
			(?:\|\=)|		# |=

			(?:\?)|			# ?:
			
			# MACRO & MULTILINE:
			(?:\\)|			# \
			
			(?:\A)|			# begin of the document
			
			# DATA TYPES:
			(?:_t)|			# _t ending types
			(?:char)|		# char
			(?:short)|		# short
			(?:int)|		# int
			(?:long)|		# long
			(?:float)|		# float
			(?:double)|		# double
			(?:void)|		# void
			(?:bool)|		# bool
			(?:string)|		# string
			
			# CONSTRUCTIONS WITH RESERVED WORDS
			(?:return\s+)
			
			#--------------------------------------------
			# custom_data_types:
			# comment this block if you don't need this
			
			## redis:
			#|
			#(?:redis_(?:[a-zA-Z0-9_]+)\s+)
			#|
			#(?:[^_0-9A-Za-z]SOCKET\s+)
			
			#--------------------------------------------
		)
		
		# EMPTY STUFF:
		(?:\s*)
	)
	
	_placeholder_
	
	(
		(?=						# this bracket is needed to worked on lexems with intersected context - for example, foo(foo())
			# EMPTY STUFF:
			(?:\s*)
			
			# SUFFIXES:
			(?:
				# COMMON CONSTRUCTIONS:
				(?:\;)|			# ;		if it's end of the statement
				(?:\=)|			# =		if it's lvalue
				(?:\.)|			# .		if it's object name
				(?:\()|			# (		if it's function
				(?:\))|			# )		if it's last param in function calling
				(?:\,)|			# ,		if it's not last param in function calling
				(?:\{)|			# {		if it's struct or class
				(?:\:)|			# :		if it's bit field
				(?:\])|			# ]		if it's index in some array
				
				# OPERATORS:
				(?:\+)|			# plus
				(?:\-)|			# minus
				(?:\*)|			# multiply
				(?:\/)|			# div
				(?:\%)|			# modulus div
				
				(?:\+\+)|		# increment
				(?:\-\-)|		# decrement
				
				(?:==)|			# equal
				(?:!=)|			# not equal
				(?:>)|			# more
				(?:>=)|			# more or equal
				(?:<)|			# less
				(?:<=)|			# less or equal
				
				(?:\&\&)|		# and
				(?:\!\!)|		# or
				(?:\!)|			# not

				(?:\&)|			# bitwise and
				(?:\|)|			# bitwise or
				(?:\^)|			# bitwise xor
				(?:\~)|			# bitwise not
				(?:<<)|			# shift left
				(?:>>)|			# shift right

				(?:\+\=)|		# +=
				(?:\-\=)|		# -=
				(?:\*\=)|		# *=
				(?:\/\=)|		# 
				(?:\%\=)|		# %=
				(?:\<\<\=)|		# <<=
				(?:\>\>\=)|		# >>=
				(?:\&\=)|		# &=
				(?:\^\=)|		# ^=
				(?:\|\=)|		# |=

				(?:\?)|			# ?:
				
				# MACRO & MULTILINE:
				(?:\\)			# \
			)
		)
	)
	/mx
	;

#---------------------------------------------------------------------------------------------------
# usage

if ($#ARGV != 0){
	print "usage: refactorer.pl path";
	exit();
}

#---------------------------------------------------------------------------------------------------
# extract files which we needed (by extension)

my $path = $ARGV[0];

my @all_child_fullpaths = give_all_child_fullpaths($path);
my $ext_regex = give_me_extnsions_regex();
my @files_for_replacing = grep {/$ext_regex/} @all_child_fullpaths;

#---------------------------------------------------------------------------------------------------
# handle every file

for(my $i=0; $i < @files_for_replacing; $i++){
	
	#-----------------------------------------------------------------------------------------------
	# read file
	
	undef $/;
	open IFHANDLE, $files_for_replacing[$i] or die "can't open file $files_for_replacing[$i] - $!";
	my $file_body = <IFHANDLE>;
	close IFHANDLE;
	
	#-----------------------------------------------------------------------------------------------
	# check (and handle if found) every replacer pair
	
	my $was_changed_file = 0;
	while ( (my $src, my $dst) = each %replacer ){
		
		my $heur_impl = $heur_context_pattern_template;
		$heur_impl =~ s/_placeholder_/$src/;
		
		if ($file_body =~ m/$heur_impl/){
			$was_changed_file = 1;
			$file_body =~ s/$heur_impl/$1$dst$2/g;
		}
	}
	
	#-----------------------------------------------------------------------------------------------
	# backup only if we needed it
	
	if ($was_changed_file == 1){

		# output that we found something
		print "$files_for_replacing[$i]\n";
		
		# make backup
		my $bak_name = give_nearest_free_bak_name($files_for_replacing[$i]);
		copy($files_for_replacing[$i],$bak_name);
		
		# delete old file
		unlink $files_for_replacing[$i];
		
		# write new file
		open(OFHANDLE, '>:raw', $files_for_replacing[$i]) or die "can't open on write file $files_for_replacing[$i] - $!";
		print OFHANDLE $file_body;
		close OFHANDLE;
	}
}
