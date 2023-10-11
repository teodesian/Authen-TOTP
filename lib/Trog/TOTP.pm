package Trog::TOTP;

use strict;
use warnings;

use 5.006;
use v5.14.0;    # Before 5.006, v5.10.0 would not be understood.

# ABSTRACT: Fork of Authen::TOTP 

use Ref::Util qw{is_coderef};
use Digest::SHA();
use Encode::Base2N();

use Carp::Always;

=head1 NAME

Trog::TOTP - Interface to RFC6238 two factor authentication (2FA)

=head1 DESCRIPTION

C<Trog::TOTP> is a fork of C<Authen::TOTP>.

While patches were initially merged upstream, no CPAN releases happened, so here we are.

=head1 USAGE

 my $gen = new Authen::TOTP(
     # not needed when setting up TOTP for the first time; we generate a secret automatically which you should grab and store.
	 secret		=>	"some_random_stuff",
     # ACHTUNG! lots of TOTP apps on various devices straight up ignore this field and hardcode 30s periods.  So probably best to never touch this.
     period     => 30,
     # callback used when emitting messages; use me for integrating into your own logging framework
     logger     => sub { my $msg = shift; ... },
 );

 # Be sure to store this as binary data
 my $secret = $get->secret();

 # This is what you will want to show users for input into their TOTP apps when their camera is failing
 my $b32secret = $gen->base32secret();

 # will generate a TOTP URI, suitable to use in a QR Code
 my $uri = $gen->generate_otp(user => 'user\@example.com', issuer => "example.com");

 # use Imager::QRCode to plot the secret for the user
 use Imager::QRCode;
 my $qrcode = Imager::QRCode->new(
       size          => 4,
       margin        => 3,
       level         => 'L',
       casesensitive => 1,
       lightcolor    => Imager::Color->new(255, 255, 255),
       darkcolor     => Imager::Color->new(0, 0, 0),
 );

 my $img = $qrcode->plot($uri);
 $img->write(file => "totp.png", type => "png");

 #compare user's OTP with computed one
 if ($gen->validate_otp(otp => <user_input>, secret => <stored_secret>, tolerance => 1)) {
	#2FA success
 }
 else {
	#no match
 }

  # Just print out the dang code
  print $gen->expected_totp_code(time);

=cut

=head1 new Authen::TOTP

 my $gen = new Authen::TOTP(
	 digits 	=>	[6|8],
	 period		=>	[30|60],
	 algorithm	=>	"SHA1", #SHA256 and SHA512 are equally valid
	 secret		=>	"some_random_stuff",
	 when		=>	<some_epoch>,
	 tolerance	=>	0,
     logger     => sub { my $msg=shift; ... },
 );

=head2 Parameters/Properties (defaults listed)

=over 4

=item digits

C<6>=> How many digits to produce/compare

=item period

C<30>=> OTP is valid for this many seconds

=item algorithm

C<SHA1>=> supported values are SHA1, SHA256 and SHA512, although most clients only support SHA1 AFAIK

=item secret

C<random_20byte_string>=> Secret used as seed for the OTP

=item base32secret

C<base32_encoded_random_12byte_string>=> Alternative way to set secret (base32 encoded)

=item when

C<epoch>=> Time used for comparison of OTPs

=item tolerance

C<1>=> Due to time sync issues, you may want to tune this and compare
this many OTPs before and after

=item logger

Log callback subroutine.  Use to integrate various messages from this modules into your logging framework.

=item DEBUG

Turn on extended log messaging.

=back

=cut

sub new {
    my $this  = shift;
    my $class = ref($this) || $this;
    my $self  = {};
    bless $self, $class;

    return $self->initialize(@_);
}

sub initialize {
    my $self = shift;

    $self->{DEBUG} //= 0;

    if ( @_ != 0 ) {
        if ( ref $_[0] eq 'HASH' ) {
            my $hash = $_[0];
            foreach ( keys %$hash ) {
                $self->{ lc $_ } = $hash->{$_};
            }
        }
        elsif ( !( scalar(@_) % 2 ) ) {
            my %hash = @_;
            foreach ( keys %hash ) {
                $self->{ lc $_ } = $hash{$_};
            }
        }
    }

    $self->valid_digits();
    $self->valid_period();
    $self->valid_algorithm();
    $self->valid_when();
    $self->valid_tolerance();
    $self->valid_secret();

    return $self;
}

=head1 METHODS

=cut

sub logger {
    return $self->{logger}->(@_) if is_coderef($self->{logger});
    warn @_;
}

sub debug_print {
    my $self = shift;
    return unless $self->{DEBUG};
    $self->logger(@_);

    return 1;
}

sub process_sub_arguments {
    my $self = shift;

    my $args  = shift;
    my $wants = shift;
    my @rets;

    if ( @$args != 0 ) {
        if ( ref $args->[0] eq 'HASH' ) {
            foreach my $want (@$wants) {
                push @rets, $args->[0]->{$want};
            }
        }
        elsif ( !( scalar(@$args) % 2 ) ) {
            my %hash = @$args;
            foreach my $want (@$wants) {
                push @rets, $hash{$want};
            }
        }
    }
    return @rets;
}

sub valid_digits {
    my $self   = shift;
    my $digits = shift;

    if ( $digits && $digits =~ m|^[68]$| ) {
        $self->{digits} = $digits;
    }
    elsif ( !defined( $self->{digits} ) || $self->{digits} !~ m|^[68]$| ) {
        $self->{digits} = 6;
    }
    1;
}

sub valid_period {
    my $self   = shift;
    my $period = shift;

    if ( $period && $period =~ m|^[36]0$| ) {
        $self->{period} = $period;
    }
    elsif ( !defined( $self->{period} ) || $self->{period} !~ m|^[36]0$| ) {
        $self->{period} = 30;
    }
    1;
}

sub valid_algorithm {
    my $self      = shift;
    my $algorithm = shift;

    if ( $algorithm && $algorithm =~ m|^SHA\d+$| ) {
        $self->{algorithm} = $algorithm;
    }
    elsif ( !defined( $self->{algorithm} ) || $self->{algorithm} !~ m|^SHA\d+$| ) {
        $self->{algorithm} = "SHA1";
    }
    1;
}

sub valid_when {
    my $self = shift;
    my $when = shift;

    if ( $when && $when =~ m|^\-?\d+$| ) {    #negative epoch is valid, though not sure how useful :)
        $self->{when} = $when;
    }
    elsif ( !defined( $self->{when} ) || $self->{when} !~ m|^\-?\d+$| ) {
        $self->{when} = time;
    }
    1;
}

sub valid_tolerance {
    my $self      = shift;
    my $tolerance = shift;

    if ( $tolerance && $tolerance =~ m|^\d+$| && $tolerance > 0 ) {
        $self->{tolerance} = ( $tolerance - 1 );
    }
    elsif ( !defined( $self->{tolerance} ) || $self->{tolerance} !~ m|^\d+$| ) {
        $self->{tolerance} = 0;
    }
    1;
}

sub valid_secret {
    my $self = shift;
    my ( $secret, $base32secret ) = @_;

    if ($secret) {
        $self->{secret} = $secret;
    }
    elsif ($base32secret) {
        $self->{secret} = $self->base32dec($base32secret);
    }
    else {
        if ( defined( $self->{base32secret} ) ) {
            $self->{secret} = $self->base32dec( $self->{base32secret} );
        }
        else {
            if ( defined( $self->{algorithm} ) ) {
                if ( $self->{algorithm} eq "SHA512" ) {
                    $self->{secret} = $self->gen_secret(64);
                }
                elsif ( $self->{algorithm} eq "SHA256" ) {
                    $self->{secret} = $self->gen_secret(32);
                }
                else {
                    $self->{secret} = $self->gen_secret(20);
                }
            }
            else {
                $self->{secret} = $self->gen_secret(20);
            }
        }
    }

    $self->{base32secret} = $self->base32enc( $self->{secret} );
    1;
}

sub secret {
    my $self = shift;
    return $self->{secret};
}

sub base32secret {
    my $self = shift;
    return $self->{base32secret};
}

sub algorithm {
    my $self      = shift;
    my $algorithm = shift;
    $self->valid_algorithm($algorithm);

    return $self->{algorithm};
}

sub hmac {
    my $self = shift;
    my $Td   = shift;
    if ( $self->{algorithm} eq 'SHA512' ) {
        return Digest::SHA::hmac_sha512_hex( $Td, $self->{secret} );
    }
    elsif ( $self->{algorithm} eq 'SHA256' ) {
        return Digest::SHA::hmac_sha256_hex( $Td, $self->{secret} );
    }
    else {
        return Digest::SHA::hmac_sha1_hex( $Td, $self->{secret} );
    }
}

sub base32enc {
    my $self = shift;
    return Encode::Base2N::encode_base32(shift);
}

sub base32dec {
    return Encode::Base2N::decode_base32(shift);
}

=head2 expected_totp_code( TIME_T $when )

Returns what a code "ought" to be at any given unix timestamp.
Useful for integrating into command line tooling to fix things when people have "tecmological differences" with their telephone.

=cut

sub expected_totp_code {
    my ( $self, $when ) = @_;
    $self->debug_print( "using when $when (" . ( $when - $self->{when} ) . ")" );

    my $T  = sprintf( "%016x", int( $when / $self->{period} ) );
    my $Td = pack( 'H*', $T );

    my $hmac = $self->hmac($Td);

    # take the 4 least significant bits (1 hex char) from the encrypted string as an offset
    my $offset = hex( substr( $hmac, -1 ) );

    # take the 4 bytes (8 hex chars) at the offset (* 2 for hex), and drop the high bit
    my $encrypted = hex( substr( $hmac, $offset * 2, 8 ) ) & 0x7fffffff;

    return sprintf( "%0" . $self->{digits} . "d", ( $encrypted % ( 10**$self->{digits} ) ) );
}


sub gen_secret {
    my $self   = shift;
    my $length = shift || 20;

    my $secret;
    for my $i ( 0 .. int( rand($length) ) + $length ) {
        $secret .= join '', ( '/', 1 .. 9, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', 'A' .. 'H', 'J' .. 'N', 'P' .. 'Z', 'a' .. 'h', 'm' .. 'z' )[ rand 58 ];
    }
    if ( length($secret) > ( $length + 1 ) ) {
        $self->debug_print( "have len " . length($secret) . " ($secret) so cutting down" );
        return substr( $secret, 0, $length );
    }
    return $secret;
}

=head2 generate_otp

Create a TOTP URI using the parameters specified or the defaults from
the new() method above

Usage:

 $gen->generate_otp(
	 digits 	=>	[6|8],
	 period		=>	[30|60],
	 algorithm	=>	"SHA1", #SHA256 and SHA512 are equally valid
	 secret		=>	"some_random_stuff",
	 issuer		=>	"example.com",
	 user		=>	"some_identifier",
 );

 Google Authenticator displays <issuer> (<user>) for a TOTP generated like this

=cut

sub generate_otp {
    my $self = shift;
    my ( $digits, $period, $algorithm, $secret, $base32secret, $issuer, $user ) =
      $self->process_sub_arguments( \@_, [ 'digits', 'period', 'algorithm', 'secret', 'base32secret', 'issuer', 'user' ] );

    unless ($user) {
        die "need user to use as prefix in generate_otp()";
    }

    $self->valid_digits($digits);
    $self->valid_period($period);
    $self->valid_algorithm($algorithm);
    $self->valid_secret( $secret, $base32secret );

    if ($issuer) {
        $issuer = qq[&issuer=] . $issuer;
    }
    else {
        $issuer = '';
    }

    return qq[otpauth://totp/$user?secret=] . $self->{base32secret} . qq[&algorithm=] . $self->{algorithm} . qq[&digits=] . $self->{digits} . qq[&period=] . $self->{period} . $issuer;
}

=head2 validate_otp

Compare a user-supplied TOTP using the parameters specified. Obviously the secret
MUST be the same secret you used in generate_otp() above/
Returns 1 on success, undef if OTP doesn't match

Usage:

 $gen->validate_otp(
	 digits 	=>	[6|8],
	 period		=>	[30|60],
	 algorithm	=>	"SHA1", #SHA256 and SHA512 are equally valid
	 secret		=>	"the_same_random_stuff_you_used_to_generate_the_TOTP",
	 when		=>	<epoch_to_use_as_reference>,
	 tolerance	=>	<try this many iterations before/after when>
	 otp		=>	<OTP to compare to>
 );

=cut


sub validate_otp {
    my $self = shift;
    my ( $digits, $period, $algorithm, $secret, $when, $tolerance, $base32secret, $otp ) =
      $self->process_sub_arguments( \@_, [ 'digits', 'period', 'algorithm', 'secret', 'when', 'tolerance', 'base32secret', 'otp' ] );

    unless ( $otp && $otp =~ m|^\d{6,8}$| ) {
        $otp ||= "";
        die "invalid otp $otp passed to validate_otp()";
    }

    $self->valid_digits($digits);
    $self->valid_period($period);
    $self->valid_algorithm($algorithm);
    $self->valid_when($when);
    $self->valid_tolerance($tolerance);
    $self->valid_secret( $secret, $base32secret );

    my @tests = ( $self->{when} );
    for my $i ( 1 .. $self->{tolerance} ) {
        push @tests, ( $self->{when} - ( $self->{period} * $i ) );
        push @tests, ( $self->{when} + ( $self->{period} * $i ) );
    }

    foreach $when (@tests) {
        my $code = $self->expected_totp_code( $when );
        $self->debug_print("comparing $code to $otp");
        return 1 if $code eq sprintf( "%0" . $self->{digits} . "d", $otp );
    }

    return undef;
}


1;
