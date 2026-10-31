module example.com/faulty

go 1.26

require github.com/anchore/grype v0.0.0

replace github.com/anchore/grype => ../fakegrype
