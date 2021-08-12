---
title: "Content Hints"
linkTitle: "Content Hints"
weight: 5
---


Anchore Engine includes the ability to read a user-supplied 'hints' file to allow users to add software artifacts to Anchore's
analysis report.  The hints file, if present, contains records that describe a software package characteristics explicitly,
and are then added to the software bill of materials (SBOM).  For example, if the owner of a CI/CD container build process 
knows that there are some 
software packages installed explicitly in a container image, but Anchore's regular analyzers fail to identify them, this mechanism 
can be used to include that information in the image's SBOM, exactly as if the packages were discovered normally. 

Hints cannot be used to modify the findings of Anchore's analyzer beyond adding new packages to the report. If a user specifies
a package in the hints file that is found by Anchore's image analyzers, the hint is ignored and a warning message is logged 
to notify the user of the conflict. 

### Configuration

See [Configuring Content Hints]({{< ref "/docs/install/configuration/content_hints" >}})

Once enabled, the analyzer services will look for a file with a specific name, location and format located within the container image - ```/anchore_hints.json```.  
The format of the file is illustrated using some examples, below.


### OS Package Records

OS Packages are those that will represent packages installed using OS / Distro style package managers.  Currently supported package types are ```rpm, dpkg, apkg``` 
for RedHat, Debian, and Alpine flavored package managers respectively.  Note that, for OS Packages, the name of the package is unique per SBOM, meaning 
that only one package named 'somepackage' can exist in an image's SBOM, and specifying a name in the hints file that conflicts with one with the same name 
discovered by the Anchore analyzers will result in the record from the hints file taking precedence (override).

* Minimum required values for a package record in anchore_hints.json

```
	{
	    "name": "musl",
	    "version": "1.1.20-r8",
	    "type": "apkg"
	}
```

* Complete record demonstrating all of the available characteristics of a software package that can be specified

```
	{
	    "name": "musl",
	    "version": "1.1.20",
	    "release": "r8",
	    "origin": "Timo Ter\u00e4s <timo.teras@iki.fi>",
	    "license": "MIT",
	    "size": "61440",
	    "source": "musl",
	    "files": ["/lib/ld-musl-x86_64.so.1", "/lib/libc.musl-x86_64.so.1", "/lib"],
	    "type": "apkg"
	}
```

### Non-OS/Language Package Records

Non-OS / language package records are similar in form to the OS package records, but with some extra/different characteristics being supplied, namely 
the ```location``` field.  Since multiple non-os packages can be installed that have the same name, the location field is particularly important as it 
is used to distinguish between package records that might otherwise be identical.  Valid types for non-os packages are currently ```java, python, gem, npm, nuget, go, binary```.  
For the latest types that are available, see the ```anchore-cli image content <someimage>``` output, which lists available types for any given deployment of Anchore Engine.

* Minimum required values for a package record in anchore_hints.json

```
	{
	    "name": "wicked",
	    "version": "0.6.1",  
	    "type": "gem"
	}
```

* Complete record demonstrating all of the available characteristics of a software package that can be specified

```
	{
	    "name": "wicked",
	    "version": "0.6.1",
	    "location": "/app/gems/specifications/wicked-0.9.0.gemspec",
	    "origin": "schneems",
	    "license": "MIT",
	    "source": "http://github.com/schneems/wicked",
	    "files": ["README.md"],
	    "type": "gem"	    
	}
```

### Putting it all together

Using the above examples, a complete anchore_hints.json file, when discovered by Anchore Engine located in ```/anchore_hints.json``` inside any container image, is provided here:

```
{
    "packages": [
	{
	    "name": "musl",
	    "version": "1.1.20-r8",
	    "type": "apkg"
	},
	{
	    "name": "wicked",
	    "version": "0.6.1",  
	    "type": "gem"
	}
    ]
}
```

With such a hints file in an image based for example on ```alpine:latest```, the resulting image content would report these two package/version records 
as part of the SBOM for the analyzed image, when viewed using ```anchore-cli image content <image> os``` and ```anchore-cli image content <image> gem``` 
to view the ```musl``` and ```wicked``` package records, respectively.


##### Note about using the hints file feature

The hints file feature is disabled by default, and is meant to be used in very specific circumstances where a trusted entity is entrusted with creating 
and installing, or removing an anchore_hints.json file from all containers being built.  It is not meant to be enabled when the container image builds 
are not explicitly controlled, as the entity that is building container images could override any SBOM entry that Anchore would normally discover, which 
affects the vulnerability/policy status of an image.  For this reason, the feature is disabled by default and must be explicitly enabled in configuration 
only if appropriate for your use case .
