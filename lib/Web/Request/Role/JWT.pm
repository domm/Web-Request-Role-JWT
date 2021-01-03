package Web::Request::Role::JWT;

# ABSTRACT: Accessors for JSON Web Token (JWT) stored in psgix

# VERSION

use 5.010;
use Moose::Role;
use HTTP::Throwable::Factory qw(http_throw);
use Log::Any qw($log);

=method get_jwt

  my $raw_token = $req->get_jwt;

Returns the raw token, so you can inspect it, or maybe pass it along to some other endpoint.

If you want to store your token somewhere else than the default C<<
$env->{'psgix.token'} >>, you have to provide another implementation
for this method.

=cut

sub get_jwt {
    my $self = shift;

    return $self->env->{'psgix.token'};
}

=method get_jwt_claims

  my $claims = $req->get_jwt_claims;

Returns all the claims as a hashref.

If you want to store your claims somewhere else than the default C<<
$env->{'psgix.claims'} >>, you have to provide another implementation
for this method.

=cut

sub get_jwt_claims {
    my $self = shift;

    return $self->env->{'psgix.claims'};
}

=method get_jwt_claim_sub

  my $sub = $req->get_jwt_claim_sub;

Get the C<sub> claim: L<https://tools.ietf.org/html/rfc7519#section-4.1.2>

=cut

sub get_jwt_claim_sub {
    my $self = shift;

    my $claims = $self->get_jwt_claims;
    return unless $claims && ref($claims) eq 'HASH';
    return $claims->{sub};
}

=method get_jwt_claim_aud

  my $aud = $req->get_jwt_claim_aud;

Get the C<aud> claim: L<https://tools.ietf.org/html/rfc7519#section-4.1.3>

=cut

sub get_jwt_claim_aud {
    my $self = shift;

    my $claims = $self->get_jwt_claims;
    return unless $claims && ref($claims) eq 'HASH';
    return $claims->{aud};
}

=method requires_jwt

  my $raw_token = $req->requires_jwt;

Returns the raw token. If no token is available, throws a L<HTTP::Throwable::Role::Status::Unauthorized> exception (aka HTTP Status 401)

=cut

sub requires_jwt {
    my $self = shift;

    my $token = $self->get_jwt;
    return $token if $token;

    $log->error("No JWT found in request");
    http_throw( 'Unauthorized' => { www_authenticate => 'bearer' } );
}

=method requires_jwt_claims

  my $claims = $req->requires_jwt_claims;

Returns all the claims as a hashref. If no claims are available, throws a L<HTTP::Throwable::Role::Status::Unauthorized> exception (aka HTTP Status 401)

=cut

sub requires_jwt_claims {
    my $self = shift;

    my $claims = $self->get_jwt_claims;
    return $claims if $claims;

    $log->error("No claims found in JWT");
    http_throw( 'Unauthorized' => { www_authenticate => 'bearer' } );
}

=method requires_jwt_claim_sub

  my $sub = $req->requires_jwt_claim_sub;

Returns the C<sub> claim. If the C<sub> claim is missing, throws a L<HTTP::Throwable::Role::Status::Unauthorized> exception (aka HTTP Status 401)

=cut

sub requires_jwt_claim_sub {
    my $self = shift;

    my $sub = $self->get_jwt_claim_sub;

    return $sub if $sub;

    $log->error("Claim 'sub' not found in JWT");
    http_throw( 'Unauthorized' => { www_authenticate => 'bearer' } );
}

=method requires_jwt_claim_aud

  my $aud = $req->requires_jwt_claim_aud;

Returns the C<aud> claim. If the C<aud> claim is missing, throws a L<HTTP::Throwable::Role::Status::Unauthorized> exception (aka HTTP Status 401)

=cut

sub requires_jwt_claim_aud {
    my $self = shift;

    my $aud = $self->get_jwt_claim_aud;

    return $aud if $aud;

    $log->error("Claim 'aud' not found in JWT");
    http_throw( 'Unauthorized' => { www_authenticate => 'bearer' } );
}

1;

=head1 SYNOPSIS

  # Create a request handler
  package My::App::Request;
  use Moose;
  extends 'Web::Request';
  with 'Web::Request::Role::JWT';

  # Finally, in some controller action
  sub action_that_needs_a_user_stored_in_jwt {
      my ($self, $req) = @_;

      my $sub   = $req->requires_jwt_claim_sub;

      my $data  = $self->model->do_something( $sub );
      return $self->json_response( $data );
  }

=head1 DESCRIPTION

C<Web::Request::Role::JWT> provides a few accessor and helper methods
that make accessing JSON Web Tokens (JWT) stored in your PSGI C<$env>
easier.

It works especially well when used with
L<Plack::Middleware::Auth::JWT>, which will validate the token and
extract the payload into the PSGI C<$env>.

=head1 METHODS

=head2 requires_* and logging

If a C<requires_*> method fails, it will log an error via L<Log::Any>.

=head1 THANKS

Thanks to

=over

=item *

L<validad.com|https://www.validad.com/> for supporting Open Source.

=back

