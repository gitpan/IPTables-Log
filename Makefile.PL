# Makefile.PL
# $Id: Makefile.PL 16 2009-10-20 14:10:00Z andys $

use 5.010000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'IPTables::Log',
    VERSION_FROM      => 'lib/IPTables/Log.pm', # finds $VERSION
    PREREQ_PM         => {'Data::GUID', 'NetAddr::IP'}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/IPTables/Log.pm', # retrieve abstract from module
       AUTHOR         => 'root <root@>') : ()),
);
