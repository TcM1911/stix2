# stix2
A pure Go library for working with Structured Threat Information Expression
(STIX™) version 2.x data.

## Parsing STIX JSON data

The library provides a helper function to parse STIX JSON. It can handle
both the bundle object and JSON objects as a JSON array. The function returns
a `StixCollection` object that holds all the extracted STIX objects.

```go
collection, err := stix2.FromJSON(jsonData)
```

## To-do

- [ ] Provide a solution to create a bundle from the collection object.
- [ ] Add more data validations when creating objects
- [ ] Support and documentation for customization
- [ ] Ensure SITX 2.0 is supported

