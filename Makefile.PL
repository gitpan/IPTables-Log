# Makefile.PL
# $Id: Makefile.PL 17 2009-12-15 01:36:48Z andys $

use 5.010000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'IPTables::Log',
    VERSION_FROM      => 'lib/IPTables/Log.pm', # finds $VERSION
    PREREQ_PM         => {'Data::GUID' => 0.045, 'NetAddr::IP' => 4.027}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/IPTables/Log.pm', # retrieve abstract from module
       AUTHOR         => 'Andy Smith <ams@meh.org.uk>') : ()),
);
