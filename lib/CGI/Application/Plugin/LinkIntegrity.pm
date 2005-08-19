
package CGI::Application::Plugin::LinkIntegrity;

use warnings;
use strict;

=head1 NAME

CGI::Application::Plugin::LinkIntegrity - Make tamper-resisistent links in CGI::Application

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

In your application:

    use base 'CGI::Application';
    use CGI::Application::Plugin::LinkIntegrity;

    sub setup {
        my $self = shift;
        $self->link_integrity_config(
            secret => 'some secret string known only to you and me',
        );
    }

    sub account_info {
        my $self = shift;

        my $account_id = get_user_account_id();

        my $template = $self->load_tmpl('account.html');

        $template->param(
            'balance'    => $self->make_link("/account.cgi?rm=balance&acct_id=$account_id");
            'transfer'   => $self->make_link("/account.cgi?rm=transfer&acct_id=$account_id");
            'withdrawal' => $self->make_link("/account.cgi?rm=withdrawl&acct_id=$account_id");
        );
    }

In your template:

    <h1>Welcome to The Faceless Banking Corp.</h1>
    <h3>Actions:</h3>
    <br /><a href="<TMPL_VAR NAME="balance">">Show Balance</a>
    <br /><a href="<TMPL_VAR NAME="transfer">">Make a Transfer</a>
    <br /><a href="<TMPL_VAR NAME="withdrawal">">Get Cash</a>


This will send the following HTML to the browser:

    <h1>Welcome to The Faceless Banking Corp.</h1>
    <h3>Actions:</h3>
    <br /><a href="/account.cgi?rm=balance&acct_id=73&_checksum=1d7c4b82d075785de04fa6b98b572691">Show Balance</a>
    <br /><a href="/account.cgi?rm=transfer&acct_id=73&_checksum=d41d8cd98f00b204e9800998ecf8427e">Make a Transfer</a>
    <br /><a href="/account.cgi?rm=withdrawl&acct_id=73&_checksum=3c5ad17bdeef3c4281abd39c6386cfd6">Get Cash</a>

The URLs created are now tamper-resistent.  If the user changes
C<acct_id> from C<73> to C<74>, the C<_checksum> will not match, and the
system will treat it as an intrusion attempt.

=head1 DESCRIPTION

C<CGI::Application::Plugin::LinkIntegrity> lets you create
tamper-resistent links within your CGI::Application project.  When you
create an URL with C<make_link>, a C<_checksum> is added to the URL:

    my $link = $self->make_link("/account.cgi?rm=balance&acct_id=73");
    print $link; # /account.cgi?rm=balance&acct_id=73&_checksum=1d7c4b82d075785de04fa6b98b572691

The checksum is a (cryptographic) hash of the URL, plus a secret string
known only to the server.

If the user attempts to change part of the URL (e.g. a query string
parameter, or the PATH_INFO), then the checksum will not match.  The run
mode will be changed to C<link_tampered>, and the C<invalid_checksum>
hook will be called.

You can define the C<link_tampered> run mode yourself, or you can use
the default C<link_tampered> run mode built into
L<CGI::Application::Plugin::LinkIntegrity>.

You can disable link checking during development by passing a true value
to the C<disable> parameter of C<< $self->link_integrity_config >>.

=cut

use Carp;

use Digest::HMAC;
use URI;
use URI::QueryParam;

use Exporter;
use vars qw(
    @ISA
    @EXPORT
    $Default_Secret
);


@ISA    = qw(Exporter);
@EXPORT = qw(make_link make_self_link link_integrity_config);

sub import {
    my $caller = scalar(caller);
    $caller->add_callback('prerun', \&_check_link_integrity);
    goto &Exporter::import;
}

CGI::Application->new_hook('invalid_checksum');

=head1 METHODS

=head2 link_integrity_config

Configure the L<CGI::Application::Plugin::LinkIntegrity>.  Usually, it
makes sense to configure this in the C<setup> method of your application's
base class:

    use CGI::Application::Plugin::LinkIntegrity;
    use base 'CGI::Application';
    package My::Project;

    sub setup {
        my $self = shift;

        $self->run_modes(['bad_user_no_biscuit']);
        $self->link_integrity_config(
            secret                 => 'some secret string known only to you and me',
            link_tampered_run_mode => 'bad_user_no_biscuit',
            digest_module          => 'Digest::MD5',
            disable                => 1,
        );
    }

Or you can pull in this configuration info from a config file.  For
instance, with using L<CGI::Application::Config::Context>:

    use CGI::Application::Plugin::LinkIntegrity;
    use CGI::Application::Plugin::Config::Context;

    use base 'CGI::Application';
    package My::Project;

    sub setup {
        my $self = shift;

        $self->conf->init(
            file   => 'app.conf',
            driver => 'ConfigGeneral',
        );

        my $config = $self->conf->context;

        $self->link_integrity_config($config->{'LinkIntegrity'});
        $self->run_modes([$config->{'LinkIntegrity'}{'link_tampered_run_mode'} || 'link_tampered']);
    }

Then in your configuration file:

    <LinkIntegrity>
        secret                 = some REALLY secret string
        link_tampered_run_mode = bad_user_no_biscuit
        hash_algorithm         = SHA1
        disable                = 1
    </LinkIntegrity>

This strategy allows you to enable and disable link checking on the fly
by changing the value of C<disable> in the config file.

The following configuration parameters are available:

=over 4

=item secret

A string known only to your application.  At a commandline, you can
generate a secret string with md5:

 $ perl -MDigest::MD5 -le"print Digest::MD5::md5_hex($$, time, rand(42));"

Or you can use Data::UUID:

 $ perl -MData::UUID -le"$ug = new Data::UUID; $uuid = $ug->create; print $ug->to_string($uuid)"

If someone knows your secret string, then they can generate their own
checksums on arbitrary data that will always pass the integrity check in
your application.  That's a Bad Thing, so don't let other people know
your secret string, and don't use the default secret string if you can
help it.

=item checksum_param

The name of the checksum parameter, which is added to the query string
and contains the cryptographic checksum of link. By default, this
parameter is named C<_checksum>.

=item link_tampered_run_mode

The run mode to go to when it has been detected that the user has
tampered with the link.  The default is C<link_tampered>.

See L<"The link_tampered Run Mode">, below.

=item digest_module

Which digest module to use to create the checksum.  Typically, this will
be either C<Digest::MD5> or C<Digest::SHA1>.  However any module
supported by C<Digest::HMAC> will work.

The default C<digest_module> is C<Digest::MD5>.

=item checksum_generator

If you want to provide a custom subroutine to make your own checksums,
you can define your own subroutine do it via the C<make_checksum> param.
Here's an example of one that uses Digest::SHA2:

        $self->link_integrity_config(
            checksum_generator => sub {
                my ($url, $secret) = @_;
                require Digest::SHA2;

                my $ctx = Digest::SHA2->new();
                $ctx->add($url . $secret);

                return $ctx->hexdigest;
            },
        );

=item disable

You can disable link checking entirely by setting C<disable> to a true
value.  This can be useful when you are developing or debugging the
application and you want the ability to tweak URL params without getting
busted.

=back

=cut

my %Config_Defaults = (
    secret                 => undef,
    checksum_param         => '_checksum',
    link_tampered_run_mode => undef,
    digest_module          => 'Digest::MD5',
    disable                => undef,
    checksum_generator     => undef,
    additional_data        => undef,
);

sub link_integrity_config {
    my $self = shift;


    my $args;
    if (ref $_[0] eq 'HASH') {
        $args = $_[0];
    }
    else {
        $args = { @_ };
    }

    # Clear config
    undef $self->{__PACKAGE__}{__CONFIG};
    my $config = _get_config($self, $args);

    $config->{'link_tampered_run_mode'} ||= 'link_tampered';

    my %run_modes = $self->run_modes;
    unless ($run_modes{$config->{'link_tampered_run_mode'}}) {
        $self->run_modes($config->{'link_tampered_run_mode'} => sub {
            return '<h1>Access Denied</h1>';
        });
    }
    %run_modes = $self->run_modes;

}

sub _get_config {
    my ($self, $args) = @_;

    if ($self->{__PACKAGE__}{__CONFIG}) {
        return $self->{__PACKAGE__}{__CONFIG};
    }
    my $config = $self->{__PACKAGE__}{__CONFIG} = { %Config_Defaults };

    if ($args) {
        # Check that all key names are valid
        foreach my $key (keys %$args) {
            unless (exists $config->{$key}) {
                croak "CAP::LinkIntegrity: Bad configuration key: $key\n";
            }
            $config->{$key} = $args->{$key};
        }
        # Check that checksum_generator is coderef
        if (exists $args->{'checksum_generator'}) {
            unless (ref $args->{'checksum_generator'} eq 'CODE') {
                croak "CAP::LinkIntegrity: checksum_generator must be coderef\n";
            }
        }
    }
    $config->{'link_tampered_run_mode'} ||= 'link_tampered';

    $config->{'secret'} || croak "CAP::LinkIntegrity - You need to provide a secret string to link_integrity_config";

    return $config;
}

=head2 make_link

Create a link, and add a checksum to it.

You can add parameters to the link directly in the URL:

    my $link = $self->make_link('/cgi-bin/app.cgi?var=value&var2=value2');

Or you can add them as a hashref of parameters after the URL:

    my $link = $self->make_link(
        '/cgi-bin/app.cgi',
        {
            var  => 'value',
            var2 => 'value2',
        }
    );

=cut

sub make_link {
    my $self   = shift;
    my $uri    = shift;
    my $params = shift;

    my $config = _get_config($self);

    $uri = URI->new($uri, 'http');

    my @query_form = $uri->query_form;

    if (ref $params eq 'HASH') {
        push @query_form, %$params;
    }
    elsif (ref $params eq 'ARRAY') {
        push @query_form, @$params;
    }
    elsif ($params) {
        croak 'usage $self->make_link($uri, \%params) or $self->make_link($uri, \@params)';
    }

    my $checksum = _hmac($self, $uri, $config->{'additional_data'});

    $uri->query_form(@query_form);
    $uri->query_param_append($config->{'checksum_param'} => $checksum);

    return $uri;
}

sub _hmac {
    my $self            = shift;
    my $uri             = shift;
    my $additional_data = shift;

    my $config = _get_config($self);

    my $secret = $config->{'secret'};

    my $digest;
    if ($config->{'checksum_generator'}) {
        $digest = $config->{'checksum_generator'}->($secret, $uri, $additional_data);
    }
    else {
        my $digest_module = $config->{'digest_module'} || croak "CAP::LinkIntegrity: digest_module not configured";
        eval "require $digest_module";
        if ($@) {
            carp "CAP::LinkIntegrity: Requested digest_module ($digest_module) not installed";
        }

        my $hmac = Digest::HMAC->new($secret, $digest_module);

        # Add all elements of the URL
        $hmac->add($uri->scheme     || '');
        $hmac->add($uri->authority  || '');
        $hmac->add($uri->port       || '');
        $hmac->add($uri->path       || '');

        foreach my $key (sort $uri->query_param) {
            $hmac->add('key');
            $hmac->add($key);
            $hmac->add('values');
            $hmac->add($_) for sort $uri->query_param($key);
        }

        $hmac->add($additional_data || '');
        $digest = $hmac->hexdigest;
    }
    return $digest;
}

=head2 make_self_link

Make a link to the current application, with optional parameters, and
add a checksum to the URL.

    my $link = $self->make_self_link(
        params => {
            var1 => 'value1',
            var1 => 'value2',
        },
    );

If you want to keep the existing C<PATH_INFO> that was passed to the
current application, use the C<keep_path_info> param:

    my $link = $self->make_self_link(
        keep_path_info => 1,
        params         => {
            var1 => 'value1',
            var1 => 'value2',
        },
    );

If you want to use a different C<PATH_INFO> than the one that was used in
calling the current application use the C<path_info> param:

    my $link = $self->make_self_link(
        path_info      => '/some/path',
        params         => {
            var1 => 'value1',
            var1 => 'value2',
        },
    );

=cut

sub make_self_link {
    my $self = shift;
    my %args = @_;

    my $uri;

    if ($args{'path_info'}) {
        $uri = URI->new($self->query->url);
        $uri->path_segments($uri->path_segments, $args{'path_info'});
    }
    elsif ($args{'keep_path_info'}) {
        $uri = URI->new($self->query->url(-path_info => 1));
    }
    else {
        $uri = URI->new($self->query->url);
    }

    $uri->query_form($args{'params'}) if $args{'params'};

    return $self->make_link($uri);
}

sub _check_link_integrity {
    my $self = shift;

    unless ($self->{__PACKAGE__}{__CONFIG}) {
        croak "CAP::LinkIntegrity - You need to call link_integrity_config before 'prerun' (e.g. in start or cgiapp_init)\n";
    }

    my $config = _get_config($self);


    return if $config->{'disable'};

    my $uri = URI->new($self->query->url(-path_info => 1));

    my @params;
    foreach my $name (sort $self->query->url_param) {
        foreach my $val (sort $self->query->url_param($name)) {
            push @params, $name, $val;
        }
    }

    $uri->query_form(@params);

    my $uri_checksum      = $uri->query_param_delete($config->{'checksum_param'});
    my $expected_checksum = _hmac($self, $uri, $config->{'additional_data'});

    if (($uri_checksum || '') ne ($expected_checksum || '')) {
        $self->prerun_mode($config->{'link_tampered_run_mode'});
        $self->call_hook('invalid_checksum');
    }
}


=head1 RUN MODES

=head2 The link_tampered Run Mode

Your application is redirected to this run mode when it has been
detected that the user has tampered with the link.  You can change the
name of this run mode by changing the value of the
C<link_tampered_runmode> param to C<link_integrity_config>.

L<CGI::Application::Plugin::LinkIntegrity> provides a default
C<link_tampered> run mode, which just displays a page with some stern
warning text.

You can define your own as follows:

    sub link_tampered {
        my $self = shift;
        my $template = $self->load_template('stern_talking_to');
        return $template->output;
    }

=head1 HOOKS

When a link is followed that doesn't match the checksum, the
C<invalid_checksum> hook is called.  You can add a callback to this hook
to do some cleanup such as deleting the user's session.  For instance:

    sub setup {
        my $self = shift;
        $self->add_callback('invalid_checksum' => \&bad_user);
    }

    sub bad_user {
        my $self = shift;

        # The user has been messing with the URLs, possibly trying to
        # break into the system.  We don't tolerate this behaviour.
        # So we delete the user's session:

        $self->session->delete;
    }

=head1 AUTHOR

Michael Graham, C<< <mag-perl@occamstoothbrush.com> >>

=head1 ACKNOWLEDGEMENTS

This module was based on the checksum feature originally built into
Richard Dice's L<CGI::Application::Framework>.

=head1 BUGS

Please report any bugs or feature requests to
C<bug-cgi-application-plugin-linkintegrity@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.  I will be notified, and then you'll automatically
be notified of progress on your bug as I make changes.

=head1 COPYRIGHT & LICENSE

Copyright 2005 Michael Graham, All Rights Reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of CGI::Application::Plugin::LinkIntegrity
