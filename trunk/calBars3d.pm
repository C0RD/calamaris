#==========================================================================
# Module: calamaris::calBars3d.pm
#
# Copyright
#
# calBars3d.pm Copyright (c) 2004 Michael Pophal based on 
# GD::Graph Copyright (c) 1995-1999 Martien Verbruggen.
# (http://search.cpan.org/~mverb/GDGraph-1.43/Graph.pm)
#
# All rights reserved. This package is free software; you can redistribute 
# it and/or modify it under the same terms as Perl itself.
#
# Acknowledgements
#
# Thanks to Martien Verbruggen's ingenious tool GD::Graph, which is basically
# the same, except some small changes needed for calamaris.
#==========================================================================
#
# Adapted to calamaris by: (c) 2004 Michael Pophal
#
# Based on:
#          GD::Graph::bars3d.pm,v 1.21 2000/04/15 08:59:36 mgjv
#          http://search.cpan.org/~mverb/GDGraph-1.43/Graph.pm
#          Copyright (c) 1995-1998 Martien Verbruggen
#
#--------------------------------------------------------------------------
#
#   Name:
#       calamaris::calBars3d.pm
#
# $Id: calBars3d.pm,v 3.2 2004-09-15 21:02:13 cord Exp $
#
#--------------------------------------------------------------------------
# Date		Modification				         Author
# -------------------------------------------------------------------------
# 2004AUG30 Adapted to calamaris				 staehler
#==========================================================================
package calamaris::calBars3d;

use strict;

use lib '/usr/local';
use calamaris::calAxestype3d;
use GD::Graph::bars;
use GD::Graph::utils qw(:all);
use GD::Graph::colour qw(:colours);

@calamaris::calBars3d::ISA = qw(calamaris::calAxestype3d);
$calamaris::calBars3d::VERSION = '0.63';

use constant PI => 4 * atan2(1,1);


my %Defaults = (
	# Spacing between the bars
	bar_spacing 	=> 0,
	
	# The 3-d extrusion depth of the bars
	bar_depth => 10,
);

sub initialise
{
	my $self = shift;

	my $rc = $self->SUPER::initialise();
	$self->set(correct_width => 1);

	while( my($key, $val) = each %Defaults ) { 
		$self->{$key} = $val 
	} # end while

	return $rc;
} # end initialise

sub set
{
	my $s = shift;
	my %args = @_;

	$s->{_set_error} = 0;

	for (keys %args) 
	{ 
		/^bar_depth$/ and do 
		{
			$s->{bar_depth} = $args{$_};
			delete $args{$_};
			next;
		};
	}

	return $s->SUPER::set(%args);
}


# CONTRIB Jeremy Wadsack
# This is a complete overhaul of the original GD::Graph::bars
# design, because all versions (overwrite = 0, 1, 2) 
# require that the bars be drawn in a loop of point over sets
sub draw_data
{
	my $self = shift;
	my $g = $self->{graph};

	my $bar_s = _round($self->{bar_spacing}/2);

	my $set_s = _round($self->{set_spacing}/2);
        my (%lset_space, %rset_space);
	for (1..2) { $lset_space{$_} = 0; $rset_space{$_} = 0; };
        if ($self->{set_spacing}) {
	  $lset_space{1} = $set_s;
	  $lset_space{2} = 0;
	  $rset_space{2} = $set_s;
	  $rset_space{1} = 0;
        }

	my $zero = $self->{zeropoint};

	my $i;
   my @iterate =  (0 .. $self->{_data}->num_points());
   for $i ($self->{rotate_chart} ? reverse(@iterate) : @iterate) {
		my ($xp, $t);
		my $overwrite = 0;
		$overwrite = $self->{overwrite} if defined $self->{overwrite};
		
		my $j;
      my $num_sets = ($self->{_data}->num_sets() >= 2) ? 2 : $self->{_data}->num_sets();
      my @iterate = (1 .. $num_sets);
      for $j (($self->{rotate_chart} && $self->{cumulate} == 0) ? reverse(@iterate) : @iterate) {
			my $value = $self->{_data}->get_y( $j, $i );
			my $factor = ($self->{_data}->num_sets() > 2) ? $self->{_data}->get_y( $j+2, $i ) : 0;
			next unless defined $value;

			my $bottom = $self->_get_bottom($j, $i);
         $value = $self->{_data}->get_y_cumulative($j, $i)
				if ($self->{cumulate});

			# Pick a data colour, calc shading colors too, if requested
			# cycle_clrs option sets the color based on the point, not the dataset.
			my @rgb;
			if( $self->{cycle_clrs} ) {
				@rgb = $self->pick_data_clr( $i + 1 );
			} else {
				@rgb = $self->pick_data_clr( $j );
			} # end if
			my $dsci = $self->set_clr( @rgb );
			if( $self->{'3d_shading'} ) {
				$self->{'3d_highlights'}[$dsci] = $self->set_clr( $self->_brighten( @rgb ) );
				$self->{'3d_shadows'}[$dsci]    = $self->set_clr( $self->_darken( @rgb ) );
				$self->{'3d_dshadows'}[$dsci]   = $self->set_clr( $self->_darken($self->_darken( @rgb )) );
				$self->{'3d_ddshadows'}[$dsci]   = $self->set_clr( $self->_darken($self->_darken($self->_darken( @rgb ))) );
			} # end if
			
			# contrib "Bremford, Mike" <mike.bremford@gs.com>
			my $brci;
			if( $self->{cycle_clrs} > 1 ) {
				$brci = $self->set_clr($self->pick_data_clr($i + 1));
			} else {
				$brci = $self->set_clr($self->pick_border_clr($j));
			} # end if


			# get coordinates of top and center of bar
			($xp, $t) = $self->val_to_pixel($i + 1, $value, $j);

			# calculate offsets of this bar
			my $x_offset = 0;
			my $y_offset = 0;
			if( $overwrite == 1 ) {
			#	$x_offset = $self->{bar_depth} * ($self->{_data}->num_sets() - $j);
			#	$y_offset = $self->{bar_depth} * ($self->{_data}->num_sets() - $j);
				$x_offset = $self->{bar_depth} * ($num_sets - $j);
				$y_offset = $self->{bar_depth} * ($num_sets - $j);
			}
			$t -= $y_offset;


			# calculate left and right of bar
			my ($l, $r);
         if ($self->{rotate_chart}) {
            $l = $bottom;
            ($r) = $self->val_to_pixel($i + 1, $value, $j);
         }

			if( (ref $self eq 'GD::Graph::mixed') || ($overwrite >= 1) )
			{
       			     if ($self->{rotate_chart}) {
             			$bottom = $t + $self->{x_step}/2 - $bar_s + $x_offset;
           			$t = $t - $self->{x_step}/2 + $bar_s + $x_offset;
          		     } else {
				$l = $xp - $self->{x_step}/2 + $bar_s + $x_offset;
				$r = $xp + $self->{x_step}/2 - $bar_s + $x_offset;
	 		     }
			} else {
            		     if ($self->{rotate_chart}) {
					warn "base is $t";
					#$bottom = $t - $self->{x_step}/2 
					#        + ($j) * $self->{x_step}/$self->{_data}->num_sets() 
					#        + $bar_s + $x_offset;
					#$t = $t - $self->{x_step}/2 
					#   + ($j-1) * $self->{x_step}/$self->{_data}->num_sets() 
					#   - $bar_s + $x_offset;
					$bottom = $t - $self->{x_step}/2 
					        + ($j) * $self->{x_step}/$num_sets 
					        + $bar_s + $x_offset;
					$t = $t - $self->{x_step}/2 
					   + ($j-1) * $self->{x_step}/$num_sets 
					   - $bar_s + $x_offset;
					warn "top bottom is ($t, $bottom)";
            			} else {
					#$l = $xp 
					#	- $self->{x_step}/2
					#	+ ($j - 1) * $self->{x_step}/$self->{_data}->num_sets()
					#	+ $bar_s + $x_offset;
					#$r = $xp 
					#	- $self->{x_step}/2
					#	+ $j * $self->{x_step}/$self->{_data}->num_sets()
					#	- $bar_s + $x_offset;
					$l = $xp 
						- $self->{x_step}/2
						+ ($j - 1) * $self->{x_step}/$num_sets
						+ $bar_s + $lset_space{$j} + $x_offset;
					$r = $xp 
						- $self->{x_step}/2
						+ $j * $self->{x_step}/$num_sets
						- $bar_s - $rset_space{$j} + $x_offset;
				}
			}

			if ($value >= 0) {
				# draw the positive bar
				$self->draw_bar( $g, $l, $t, $r, $bottom-$y_offset, $dsci, $brci, 0, $factor );
			} else {
				# draw the negative bar
				$self->draw_bar( $g, $l, $bottom-$y_offset, $r, $t, $dsci, $brci, -1, $factor );
			} # end if

		} # end for
	} # end for


	# redraw the 'zero' axis, front and right
	if( $self->{zero_axis} ) {
		$g->line( 
			$self->{left}, $self->{zeropoint}, 
			$self->{right}, $self->{zeropoint}, 
			$self->{fgci} );
		$g->line( 
			$self->{right}, $self->{zeropoint}, 
			$self->{right}+$self->{depth_3d}, $self->{zeropoint}-$self->{depth_3d}, 
			$self->{fgci} );
	} # end if

	# redraw the box face
	if ( $self->{box_axis} ) {
		# Axes box
		$g->rectangle($self->{left}, $self->{top}, $self->{right}, $self->{bottom}, $self->{fgci});
		$g->line($self->{right}, $self->{top}, $self->{right} + $self->{depth_3d}, $self->{top} - $self->{depth_3d}, $self->{fgci});
		$g->line($self->{right}, $self->{bottom}, $self->{right} + $self->{depth_3d}, $self->{bottom} - $self->{depth_3d}, $self->{fgci});
	} # end if

	return $self;
	
} # end draw_data


# CONTRIB Jeremy Wadsack
# This function draws a bar at the given 
# coordinates. This is called in all three 
# overwrite modes.
sub draw_bar {
	my $self = shift;
	my $g = shift;
	my( $l, $t, $r, $b, $dsci, $brci, $neg, $factor ) = @_;
	my $height = ($b - $t)*$factor;
	
	# get depth of the bar
	my $depth = $self->{bar_depth};

	# get the bar shadow depth and color
	my $bsd = $self->{shadow_depth};
	my $bsci = $self->set_clr(_rgb($self->{shadowclr}));

	my( $xi );

	# shadow
	if( $bsd > 0 ) {
		my $sb = $b - $depth;
		my $st = $t - $depth + $bsd;
		
		if( $neg != 0 ) {
			$st -= $bsd;
			if( $self->{zero_axis_only} ) {
				$sb += $bsd;
			} else {
				$sb = _min($b-$depth+$bsd, $self->{bottom}-$depth);
			} # end if
		} # end if

		# ** If this isn't the back bar, then no side shadow should be 
		#    drawn or else the top should be lowered by 
		#    ($bsd * dataset_num), it should be drawn on the back surface, 
		#    and a shadow should be drawn behind the front bar if the 
		#    bar is positive and the back is negative.
		
		$g->filledRectangle($l+$depth+$bsd,
		                    $st,
		                    $r+$depth+$bsd,
		                    $sb,
		                    $bsci);

		# Only draw bottom shadow if at the bottom and has bottom 
		# axis. Always draw top shadow
		if( ($neg == 0) || ($sb >= $self->{bottom}-$depth) ) {
			my $poly = new GD::Polygon;
			$poly->addPt( $r, $b );
			$poly->addPt( $r+$bsd, $b );
			$poly->addPt( $r+$depth+$bsd, $b-$depth );
			$poly->addPt( $r+$depth, $b-$depth );
			$g->filledPolygon( $poly, $bsci );
		} # end if

	} # end if

	# side top
	my $poly = new GD::Polygon;
	$poly->addPt( $r, $b );
	$poly->addPt( $r+$depth, $b-$depth );
	$poly->addPt( $r+$depth, $b-$depth-$height );
	$poly->addPt( $r, $b-$height );
	if( $self->{'3d_shading'} ) {
		$g->filledPolygon( $poly, $self->{'3d_ddshadows'}[$dsci] );
	} else {
		$g->filledPolygon( $poly, $dsci );
	} # end if

	# side bottom
	$poly = new GD::Polygon;
	$poly->addPt( $r, $b-$height );
	$poly->addPt( $r+$depth, $b-$depth-$height );
	$poly->addPt( $r+$depth, $t-$depth );
	$poly->addPt( $r, $t );
	if( $self->{'3d_shading'} ) {
		$g->filledPolygon( $poly, $self->{'3d_shadows'}[$dsci] );
	} else {
		$g->filledPolygon( $poly, $dsci );
	} # end if
	$g->polygon( $poly, $brci );

	# top
	#	-- only draw negative tops if the bar starts at zero
	if( ($neg == 0) || ($t <= $self->{zeropoint}) ) {
		$poly = new GD::Polygon;
		$poly->addPt( $l, $t );
		$poly->addPt( $l+$depth, $t-$depth );
		$poly->addPt( $r+$depth, $t-$depth );
		$poly->addPt( $r, $t );
		if( $self->{'3d_shading'} ) {
			$g->filledPolygon( $poly, $self->{'3d_highlights'}[$dsci] );
		} else {
			$g->filledPolygon( $poly, $dsci );
		} # end if
		$g->polygon( $poly, $brci );
	} # end if

	# face
	$g->filledRectangle( $l, $t, $r, $b-$height, $dsci );   			# face top
	$g->filledRectangle( $l, $b-$height, $r, $b, $self->{'3d_dshadows'}[$dsci] ); 	# face bottom
	$g->rectangle( $l, $t, $r, $b-$height, $brci );					# frame face top
	$g->rectangle( $l, $b-$height, $r, $b, $brci ); 				# frame face bottom

} # end draw_bar

# [JAW] Overrides axestype's set_max_min. 
# Go through the parent's process then adjust the baseline to 0 for bar graphs.
sub set_max_min {
	my $self = shift;

	$self->SUPER::set_max_min( @_ );
	
	# This code is taken from Martien's axestype.pm
	for my $i (1..($self->{two_axes} ? 2 : 1)) {
		# If at the same side of the zero axis
		if( $self->{y_max}[$i] && $self->{y_min}[$i]/$self->{y_max}[$i] > 0 ) {
			$self->{y_min}[$i] > 0 ? 
			$self->{y_min}[$i] = 0 : 
			$self->{y_max}[$i] = 0 ;
		} # end if
	} # end for

	return $self;
} # end set_max_min


# [JW] Just use the one in GD::Graph::bars
sub draw_values
{
	return &GD::Graph::bars::draw_values( @_ );
}


1;
