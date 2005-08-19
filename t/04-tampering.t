
use Test::More 'no_plan';
use strict;
$ENV{CGI_APP_RETURN_ONLY} = 1;

use URI;
use URI::QueryParam;

my $Created_Link;

{
    package WebApp;
    use CGI;
    use CGI::Application;
    use vars qw(@ISA);
    use URI;
    use URI::Escape;
    BEGIN { @ISA = ('CGI::Application'); }

    use Test::More;
    use CGI::Application::Plugin::LinkIntegrity;

    sub setup {
        my $self = shift;
        $self->header_type('none');
        $self->run_modes([qw(
            link_okay
            create_link
            bad_user_no_biscuit
            link_tampered
        )]);

        my %li_config = (
            secret  => 'extree seekrit',
        );
        if ($self->param('custom_rm')) {
            $li_config{'link_tampered_run_mode'} = 'bad_user_no_biscuit';
        }
        if ($self->param('check')) {
            $li_config{'checksum_param'} = $self->param('check');
        }
        if ($self->param('create_link')) {
            $self->start_mode('create_link');
            $li_config{'disable'} = 1;
        }
        else {
            $self->start_mode('link_okay');
        }
        $self->link_integrity_config(
            %li_config,
        );
    }

    sub link_okay {
        my $self = shift;
        return 'rm=link_okay';
    }
    sub create_link {
        my $self = shift;
        return $self->make_link($self->param('create_link'));
    }
    sub link_tampered {
        my $self = shift;
        return 'rm=link_tampered';
    }
    sub bad_user_no_biscuit {
        my $self = shift;
        return 'rm=bad_user_no_biscuit';
    }

}
###########################################################################
# Build the link
$ENV{'REQUEST_METHOD'} = 'POST';
$ENV{'SERVER_PORT'}    = '80';
$ENV{'SCRIPT_NAME'}    = '/cgi-bin/app.cgi';
$ENV{'SERVER_NAME'}    = 'www.example.com';
$ENV{'PATH_INFO'}      = '/my/happy/pathy/info';
$ENV{'QUERY_STRING'}   = 'zap=zoom&zap=zub&guff=gubbins&zap=zuzzu';

my $link = URI->new(WebApp->new(PARAMS => {
    create_link => 'http://www.example.com/script.cgi/path/info?p1=v1&p2=v2&p2=v3',
})->run);

# Validate it

$ENV{'REQUEST_METHOD'} = 'POST';
$ENV{'SERVER_PORT'}    = $link->port;
$ENV{'SCRIPT_NAME'}    = $link->path;
$ENV{'SERVER_NAME'}    = $link->authority;
$ENV{'PATH_INFO'}      = '';
$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new->run, 'rm=link_okay', '[POST] link_okay');

# remove the _checksum from the query - this should invalidate it
my $checksum = $link->query_param_delete('_checksum');
$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new->run, 'rm=link_tampered', '[POST] link_tampered (checksum removed)');

# add a bogus checksum - this should invalidate it
my $qf = $link->query_form_hash;
$qf->{'_checksum'} = 'xxxx';
$qf = $link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new->run, 'rm=link_tampered', '[POST] link_tampered (checksum changed)');


# restore original checksum - this should revalidate it
$qf = $link->query_form_hash;
$qf->{'_checksum'} = $checksum;
$qf = $link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new->run, 'rm=link_okay', '[POST] link_okay (original checksum added again)');

###########################################################################
# Same tests with method=GET
$ENV{'REQUEST_METHOD'} = 'GET';

is(WebApp->new->run, 'rm=link_okay', '[GET] link_okay');

# remove the _checksum from the query - this should invalidate it
$checksum = $link->query_param_delete('_checksum');
$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new->run, 'rm=link_tampered', '[GET] link_tampered (checksum removed)');

# add a bogus checksum - this should invalidate it
$qf = $link->query_form_hash;
$qf->{'_checksum'} = 'xxxx';
$qf = $link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new->run, 'rm=link_tampered', '[GET] link_tampered (checksum changed)');


# restore original checksum - this should revalidate it
$qf = $link->query_form_hash;
$qf->{'_checksum'} = $checksum;
$qf = $link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new(PARAMS => { 'custom_rm' => 1 })->run, 'rm=link_okay', '[GET] link_okay (original checksum added again)');


###########################################################################
# Same tests with method=XXX
$ENV{'REQUEST_METHOD'} = 'XXX';

is(WebApp->new->run, 'rm=link_okay', '[XXX] link_okay');

# remove the _checksum from the query - this should invalidate it
$checksum = $link->query_param_delete('_checksum');
$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new->run, 'rm=link_tampered', '[XXX] link_tampered (checksum removed)');

# add a bogus checksum - this should invalidate it
$qf = $link->query_form_hash;
$qf->{'_checksum'} = 'xxxx';
$qf = $link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new->run, 'rm=link_tampered', '[XXX] link_tampered (checksum changed)');


# restore original checksum - this should revalidate it
$qf = $link->query_form_hash;
$qf->{'_checksum'} = $checksum;
$qf = $link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new(PARAMS => { 'custom_rm' => 1 })->run, 'rm=link_okay', '[XXX] link_okay (original checksum added again)');


###########################################################################
# Same tests with method=BARNEY
$ENV{'REQUEST_METHOD'} = 'PUT';

is(WebApp->new->run, 'rm=link_okay', '[PUT] link_okay');

# remove the _checksum from the query - this should invalidate it
$checksum = $link->query_param_delete('_checksum');
$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new->run, 'rm=link_tampered', '[PUT] link_tampered (checksum removed)');

# add a bogus checksum - this should invalidate it
$qf = $link->query_form_hash;
$qf->{'_checksum'} = 'xxxx';
$qf = $link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new->run, 'rm=link_tampered', '[PUT] link_tampered (checksum changed)');


# restore original checksum - this should revalidate it
$qf = $link->query_form_hash;
$qf->{'_checksum'} = $checksum;
$qf = $link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new(PARAMS => { 'custom_rm' => 1 })->run, 'rm=link_okay', '[PUT] link_okay (original checksum added again)');



###########################################################################
# Same tests with custom link_tampered_run_mode
$ENV{'REQUEST_METHOD'} = 'GET';

is(WebApp->new(PARAMS => { 'custom_rm' => 1 })->run, 'rm=link_okay', '[CUSTOM RM] link_okay');

# remove the _checksum from the query - this should invalidate it
$checksum = $link->query_param_delete('_checksum');
$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new(PARAMS => { 'custom_rm' => 1 })->run, 'rm=bad_user_no_biscuit', '[CUSTOM RM] bad_user (checksum removed)');

# add a bogus checksum - this should invalidate it
$qf = $link->query_form_hash;
$qf->{'_checksum'} = 'xxxx';
$qf = $link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new(PARAMS => { 'custom_rm' => 1 })->run, 'rm=bad_user_no_biscuit', '[CUSTOM RM] bad_user (checksum changed)');


# restore original checksum - this should revalidate it
$qf = $link->query_form_hash;
$qf->{'_checksum'} = $checksum;
$qf = $link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new(PARAMS => { 'custom_rm' => 1 })->run, 'rm=link_okay', '[CUSTOM RM] link_okay (original checksum added again)');


###########################################################################
# Same tests with custom checksum_param
$ENV{'REQUEST_METHOD'} = 'GET';

is(WebApp->new(PARAMS => { 'check' => '_checksum' })->run, 'rm=link_okay', '[custom checksum] link_okay');
is(WebApp->new(PARAMS => { 'check' => '**frobnicate**' })->run, 'rm=link_tampered', '[custom checksum] link_tampered (changed checksum_param)');

# remove the _checksum from the query - this should invalidate it
$qf = $link->query_form_hash;
delete $qf->{'_checksum'};
$qf->{'**frobnicate**'} = 'xxxx';
$link->query_form_hash($qf);
$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new(PARAMS => { 'check' => '**frobnicate**' })->run, 'rm=link_tampered', '[custom checksum] link_tampered (checksum removed)');

# add a bogus checksum - this should invalidate it
delete $qf->{'**frobnicate**'};
$qf->{'xxx_frobozz_xxx'} = 'xxxx';
$link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new(PARAMS => { 'check' => 'xxx_frobozz_xxx' })->run, 'rm=link_tampered', '[custom checksum] link_tampered (checksum changed)');

# restore original checksum - this should revalidate it
delete $qf->{'xxx_frobozz_xxx'};
$qf->{'xxx_fizzle_***'} = $checksum;
$link->query_form_hash($qf);

$ENV{'QUERY_STRING'}   = $link->query;

is(WebApp->new(PARAMS => { 'check' => 'xxx_fizzle_***' })->run, 'rm=link_okay', '[custom checksum] link_okay (original checksum added again)');

###########################################################################
# Leave the checksum, alter a param

delete $qf->{'xxx_fizzle_***'};
$qf->{'_checksum'} = $checksum;
$link->query_form_hash($qf);
$ENV{'QUERY_STRING'}   = $link->query;
is(WebApp->new->run, 'rm=link_okay', '[alter param] link_okay');

# add a param
$qf->{'yyy'} = 'xxxx';
$link->query_form_hash($qf);
$ENV{'QUERY_STRING'}   = $link->query;
is(WebApp->new->run, 'rm=link_tampered', '[alter param] link_tampered (added param)');

# change a param
delete $qf->{'yyy'};
$link->query_form_hash($qf);
$ENV{'QUERY_STRING'}   = $link->query;
is(WebApp->new->run, 'rm=link_okay', '[alter param] link_okay');

$qf->{'p1'} = 'v1b';
$link->query_form_hash($qf);
$ENV{'QUERY_STRING'}   = $link->query;
is(WebApp->new->run, 'rm=link_tampered', '[alter param] link_tampered (changed param)');

$qf->{'p1'} = 'v1';
$link->query_form_hash($qf);
$ENV{'QUERY_STRING'}   = $link->query;
is(WebApp->new->run, 'rm=link_okay', '[alter param] link_okay');

# change a value
$qf->{'p2'} = ['v2', 'v3b'];
$link->query_form_hash($qf);
$ENV{'QUERY_STRING'}   = $link->query;
is(WebApp->new->run, 'rm=link_tampered', "[alter param] link_tampered (changed a param's value)");

$qf->{'p2'} = ['v2', 'v3'];
$link->query_form_hash($qf);
$ENV{'QUERY_STRING'}   = $link->query;
is(WebApp->new->run, 'rm=link_okay', '[alter param] link_okay');



# change host
$ENV{'SERVER_NAME'}    = 'www.badhost.com';
is(WebApp->new->run, 'rm=link_tampered', "[alter param] link_tampered (changed a host)");

$link->query_form_hash($qf);
$ENV{'SERVER_NAME'}    = 'www.example.com';
is(WebApp->new->run, 'rm=link_okay', '[alter param] link_okay');

# change port
$ENV{'SERVER_PORT'}    = '88';
is(WebApp->new->run, 'rm=link_tampered', "[alter param] link_tampered (changed a host)");

$link->query_form_hash($qf);
$ENV{'SERVER_PORT'}    = '80';
is(WebApp->new->run, 'rm=link_okay', '[alter param] link_okay');

# change scheme
$ENV{'HTTPS'}    = 'on';
is(WebApp->new->run, 'rm=link_tampered', "[alter param] link_tampered (changed a host)");

$link->query_form_hash($qf);
delete $ENV{'HTTPS'};
is(WebApp->new->run, 'rm=link_okay', '[alter param] link_okay');
