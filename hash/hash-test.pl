#!/usr/bin/perl -w

use strict;

use constant {
	USAGE => "Usage: ./hash-test.pl <hash-name> [<targetPath>]\n"
};

my $HashRegex = qr/([0-9a-f]+)/;

sub processDir
{
	my ( $hashName, $dirPath ) = @_;
	opendir my $dir, $dirPath or return;
	my @files = readdir $dir;
	foreach my $file ( @files )
	{
		next if ( $file eq "." or $file eq ".." );
		my $fullPath = "$dirPath/$file";
		if ( -d $fullPath )
		{
			processDir( $hashName, $fullPath );
		}
		elsif ( -f $fullPath and -r $fullPath )
		{
			my $hashOutput = `./${hashName}sum.sh "$fullPath"`;
			my $sysHashOutput = `./${hashName}sum-orig.sh "$fullPath"`;
			my ( $hash ) = $hashOutput =~ $HashRegex; 
			my ( $origHash ) = $sysHashOutput =~ $HashRegex; 
			if ( defined( $hash ) and defined( $origHash ) )
			{
				print "$fullPath: " . ( ( $hash eq $origHash ) ?
					"equal" : "no equal!!!" ) . "\n";
			}
		}
	}
}

die USAGE if ( @ARGV < 1 );
my $hashName = $ARGV[ 0 ];
my $rootDir = ".";
$rootDir = $ARGV[ 1 ] if ( @ARGV > 1 );
processDir( $hashName, $rootDir );

