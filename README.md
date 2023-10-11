# NAME

Trog::TOTP - Fork of Authen::TOTP with patches


# SYNOPSIS

    use Trog::TOTP;

# DESCRIPTION

Things not in the version of Authen::TOTP on CPAN:
    * Just require the XS dependencies straight up, and use ones that actually work
    

# ACKNOWLEDGEMENTS

Github user j256 for his example implementation

Gryphon Shafer <gryphon@cpan.org> for his [Auth::GoogleAuth](https://metacpan.org/pod/Auth%3A%3AGoogleAuth) module
that does mostly the same job, but I discovered after I had written 
most of this

# AUTHORS

Thanos Chatziathanassiou <tchatzi@arx.net>
[http://www.arx.net](http://www.arx.net)

George S. Baugh <george@troglodyne.net>
[https://troglodyne.net](https://troglodyne.net)

# COPYRIGHT

Copyright (c) 2020 arx.net - Thanos Chatziathanassiou . All rights reserved.

This program is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

See [http://www.perl.com/perl/misc/Artistic.html](http://www.perl.com/perl/misc/Artistic.html)
