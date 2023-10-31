#!/usr/bin/perl -w

use strict;

use constant {
	USAGE => "Usage: ./crypt-full.test.pl <encryptors-path> " .
		"<tmp-path> <work-path>"
};

my $encryptorsPath = $ARGV[ 0 ];
my $tmpPath = $ARGV[ 1 ];
my $workPath = $ARGV[ 2 ];

sub RunTest( $$$ )
{
	my ( $keySize, $mode, $operation ) = @_;
	my $params = "\"$encryptorsPath\" \"$tmpPath\" " .
		"$keySize 16 $mode $operation " .
		"\"$workPath\"";
	my $output = `./crypt-test.pl $params`;
	if ( length( $output ) > 0 )
	{
		print $output;
		die "some errors occured during test ( $keySize, ".
			"$mode, $operation )\n";
	}
}


# ======== Entry Point ========
die USAGE if ( @ARGV != 3 );

for my $operation ( ( "-enc", "-dec" ) )
{
	RunTest( 16, "ecb", $operation );
	RunTest( 24, "ecb", $operation );
	RunTest( 32, "ecb", $operation );
	
	RunTest( 16, "cbc", $operation );
	RunTest( 24, "cbc", $operation );
	RunTest( 32, "cbc", $operation );
	
	RunTest( 16, "cfb", $operation );
	RunTest( 24, "cfb", $operation );
	RunTest( 32, "cfb", $operation );
	
	RunTest( 16, "ofb", $operation );
	RunTest( 24, "ofb", $operation );
	RunTest( 32, "ofb", $operation );
}
