This directory contains tests to test behavior of writes in Queryable Encryption.

The following terminology is used in the examples:

A **multi-statement** write command contains multiple statements. This means multiple entries in `inserts`, `updates`, or `deletes` in the `insert`, `update`, and `delete` commands respectively. Example of a multi-statement delete:

```yml
{
    "delete" : "coll",
    "deletes" : [
        {"q" : {}, "limit" : 1},
        {"q" : {}, "limit" : 1}
    ]
}
```

A **multi-document** `update` or `delete` statement applies to (possibly) multiple documents. This means setting `multi: true` for an `update` statement, or `limit: 0` for a `delete` statement. Example of a multi-document delete:

```json
{
    "delete" : "coll",
    "deletes" : [
        {"q" : {}, "limit" : 0}
    ]
}
```


