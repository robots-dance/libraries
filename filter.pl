#!/usr/bin/perl -w

use strict;

while ( <STDIN> )
{
	chop;
	my ( $e ) = $_ =~ /(.+): no equal.+/;
	if ( $e and -f $e )
	{
		print "$e: ", -s $e, "\n";
		print `ls -l \"$e\"`, "\n";
	}
}
