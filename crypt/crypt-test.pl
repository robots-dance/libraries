#!/usr/bin/perl -w

use strict;
use experimental 'smartmatch';

use constant {
	USAGE => "./crypt-test.pl <encryptors-path> <tmp-path> " .
		"<key-size> <iv-size> <crypt-mode> <operation> [<work-dir>]\n",
	
	DEF_ROOT_PATH => ".",
	
	KEYIV_CHARS => "0123456789abcdef"
};

use constant {
	MY_ENCRYPTOR => "encryptor",
	MY_ENC_EXT => "enc",
	MY_DEC_EXT => "dec"
};

use constant {
	OPENSSL_ENCRYPTOR => "encryptor_ssl",
	OPENSSL_ENC_EXT => "enc_ssl",
	OPENSSL_DEC_EXT => "dec_ssl"
};

sub processDir( $$$$$$$ );

sub generateKey
{
	my $keySize = shift;
	my $result = "";
	for ( my $byteIndex = 0; $byteIndex < $keySize; $byteIndex++ )
	{
		my $byteVal = int( rand( 256 ) );
		$result .= substr( KEYIV_CHARS, $byteVal >> 4, 1 ); 
		$result .= substr( KEYIV_CHARS, $byteVal & 0x0F, 1 );
	}
	return $result;
}

sub generateIV
{
	my $ivSize = shift;
	return generateKey( $ivSize );
}

sub callEncryptor( $$$$$$$ )
{
	my ( $encryptorPath, $inpFilePath, $outFilePath,
		$key, $iv, $cryptMode, $operation ) = @_;
	my $cmd = sprintf(
		"\"$encryptorPath\" \"%s\" \"%s\" %s %s %s %s",
		$inpFilePath, $outFilePath,
		$key, $iv,
		$cryptMode, $operation
	);
	`$cmd`;
}

sub testEncryption( $$$$$$$ )
# Returns 1 if success, 0 otherwise
# I believe that an openssl realization is correct and use
# this fact for a test execution. I check results of an
# encryption operation for two encryptors and use this
# information for a test successfull run indication
#
{
	my ( $tmpDirPath, $fileName, $encryptorsPath, $fullPath,
		$key, $iv, $cryptMode ) = @_;
	
	my @outFiles = ();
	
	for my $encParams ( ( [ MY_ENCRYPTOR, MY_ENC_EXT ],
		[ OPENSSL_ENCRYPTOR, OPENSSL_ENC_EXT ] ) )
	{
		my $outFilePath = "$tmpDirPath/$fileName.@$encParams[ 1 ]"; 
		last if ( -f $outFilePath and not -w $outFilePath or
			-d $outFilePath );
		callEncryptor( "$encryptorsPath/@$encParams[ 0 ]",
			$fullPath, $outFilePath,
			$key, $iv,
			$cryptMode, "-enc" );
		push @outFiles, $outFilePath;
	}
	
	if ( 2 == @outFiles )
	{
		my $diffResult = `diff "$outFiles[ 0 ]" "$outFiles[ 1 ]"`;
		if ( length( $diffResult ) == 0 )
		{
			for my $outFilePath ( @outFiles ) {
				`rm -f "$outFilePath"`;
			}
		}
		else {
			return 0;
		}
	}
	else {
		return 0;
	}
	return 1;
}

sub testDecryption( $$$$$$$ )
{
	my ( $tmpDirPath, $fileName, $encryptorsPath, $fullPath,
		$key, $iv, $cryptMode ) = @_;
	
	my @outFiles = ();
	
	for my $encParams ( ( [ MY_ENCRYPTOR, MY_ENC_EXT, MY_DEC_EXT ],
		[ OPENSSL_ENCRYPTOR, OPENSSL_ENC_EXT, OPENSSL_DEC_EXT ] ) )
	{
		my $outBasePath = "$tmpDirPath/$fileName"; 
		my $encUtilPath = "$encryptorsPath/@$encParams[ 0 ]";
		
		my $outEncFilePath = "$outBasePath.@$encParams[ 1 ]";
		last if ( -f $outEncFilePath and not -w $outEncFilePath or
			-d $outEncFilePath );
		callEncryptor( $encUtilPath, 
			$fullPath, $outEncFilePath,
			$key, $iv,
			$cryptMode, "-enc" );
		
		my $outDecFilePath = "$outBasePath.@$encParams[ 2 ]";
		last if ( !$outDecFilePath and not -w $outDecFilePath or
			-d $outDecFilePath );
		callEncryptor( $encUtilPath,
			$outEncFilePath, $outDecFilePath,
			$key, $iv,
			$cryptMode, "-dec" );
		
		`rm -f "$outEncFilePath"`;
		push @outFiles, $outDecFilePath;
	}
	
	if ( 2 == @outFiles )
	{
		my $outFileIndex = 0;
		for my $outFilePath ( @outFiles )
		{
			my $diffResult = `diff "$outFilePath" "$fullPath"`;
			if ( length( $diffResult ) == 0 )
			{
				`rm -f "$outFilePath"`;
			}
			else
			{
				return 0 == $outFileIndex ? 1 : 2;
			}
			$outFileIndex++;
		}
	}
	else {
		return -1;
	}
	return 0;
}

sub processDir( $$$$$$$ )
{
	my ( $curDirPath, $encryptorsPath, $tmpDirPath,
		$keySize, $ivSize, $cryptMode, $operation ) = @_;
	opendir my $curDir, $curDirPath or return;
	my @files = readdir $curDir;
	foreach my $fileName ( @files )
	{
		next if ( $fileName eq "." or $fileName eq ".." );
		my $fullPath = "$curDirPath/$fileName";
		if ( -d $fullPath )
		{
			processDir( $fullPath, $encryptorsPath, $tmpDirPath,
				$keySize, $ivSize, $cryptMode, $operation );
		}
		elsif ( -f $fullPath and -r $fullPath )
		{
			my $key = generateKey( $keySize );
			my $iv = generateIV( $ivSize );
			
			my $operationSuccess;
			my $operInfo = "$fullPath ( key = $key, ".
				"iv = $iv, mode = $cryptMode )";
			if ( $operation eq "-enc" )
			{
				if ( not testEncryption(
					$tmpDirPath, $fileName, $encryptorsPath, $fullPath,
					$key, $iv, $cryptMode ) )
				{
					print "$operInfo: bad encryption\n";
				}

			}
			else
			{
				my $errorCode = testDecryption(
					$tmpDirPath, $fileName, $encryptorsPath, $fullPath,
					$key, $iv, $cryptMode );
				if ( $errorCode != 0 )
				{
					my $realization = "";
					if ( $errorCode != -1 )
					{
						my @realizeNames = ( "myself", "openssl" );
						$realization = ", $realizeNames[ $errorCode - 1 ]";
					}
					print "$operInfo: bad decryption$realization\n";
				}
			}
		}
	}
}


# ======== Entry Point ========
die USAGE if ( @ARGV < 6 );

# parse and check input parameters
my $rootPath = DEF_ROOT_PATH;
if ( @ARGV > 6 )
{
	$rootPath = $ARGV[ 6 ];
	$rootPath = DEF_ROOT_PATH if ( ! -d $rootPath );
}

my $encryptorsPath = $ARGV[ 0 ];
die "incorrect encryptors directory path\n" if (
	! -d $encryptorsPath or
	! -r $encryptorsPath );

my $tmpDirPath = $ARGV[ 1 ];
die "incorrect tmp file path" if (
	! -d $tmpDirPath or
	! -w $tmpDirPath );

my $keySize = int( $ARGV[ 2 ] );
die "key size isn't number\n" if ( 0 == $keySize );
die "incorrect key size\n" if ( $keySize % 2 > 0 );

my $ivSize = int( $ARGV[ 3 ] );
die "iv size isn't number\n" if ( 0 == $ivSize );
die "incorrect iv size\n" if ( $keySize % 2 > 0 );

my $cryptMode = $ARGV[ 4 ];
die "incorrect crypt mode\n" if ( not $cryptMode ~~ [
	"cbc", "cfb", "ecb", "ofb" ] );

my $operation = $ARGV[ 5 ];
die "incorrect operation\n" if ( not $operation ~~ [
	"-enc", "-dec" ] );

# run recursive tests
processDir( $rootPath, $encryptorsPath, $tmpDirPath,
	$keySize, $ivSize, $cryptMode, $operation );
