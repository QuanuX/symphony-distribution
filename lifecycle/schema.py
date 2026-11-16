"""Fail-closed validator for the JSON Schema keywords used by bound contracts.

This deliberately small subset is not a general JSON Schema implementation.
An unrecognized validation keyword refuses preparation rather than ignoring it.
Schemas are loaded only from the explicitly selected immutable Git commit.
"""
import json
import re


class SchemaError(ValueError):
    pass


KEYWORDS = set('''$schema $id $defs $comment title description default examples $ref type
    const enum required properties additionalProperties items minItems maxItems
    uniqueItems minLength maxLength pattern minimum maximum oneOf anyOf allOf
    if then else not'''.split())


def equal(a, b):
    return json.dumps(a, sort_keys=True, ensure_ascii=False) == json.dumps(b, sort_keys=True, ensure_ascii=False)


class Registry:
    def __init__(self, schemas):
        self.schemas = {value['$id']: value for value in schemas}
        if len(self.schemas) != len(schemas):
            raise SchemaError('Duplicate schema identity')
        for value in schemas:
            self._check_keywords(value)

    def _check_keywords(self, schema):
        if not isinstance(schema, dict) or set(schema) - KEYWORDS:
            raise SchemaError('Unsupported schema keyword or shape')
        for key in ('properties', '$defs'):
            for child in schema.get(key, {}).values():
                self._check_keywords(child)
        for key in ('items', 'if', 'then', 'else', 'not'):
            if key in schema:
                self._check_keywords(schema[key])
        for key in ('oneOf', 'anyOf', 'allOf'):
            for child in schema.get(key, []):
                self._check_keywords(child)
        if 'additionalProperties' in schema and type(schema['additionalProperties']) is not bool:
            raise SchemaError('Unsupported additionalProperties schema')

    def validate(self, value, identity):
        if identity not in self.schemas:
            raise SchemaError('Unbound schema reference')
        self._validate(value, self.schemas[identity], self.schemas[identity], 0)

    def _validate(self, value, schema, root, depth):
        if depth > 128:
            raise SchemaError('Schema recursion bound exceeded')
        def need(ok, message):
            if not ok:
                raise SchemaError(message)
        def valid(child):
            try:
                self._validate(value, child, root, depth + 1)
                return True
            except SchemaError:
                return False
        if '$ref' in schema:
            ref = schema['$ref']
            if ref.startswith('#/$defs/'):
                name = ref.removeprefix('#/$defs/')
                need(name in root.get('$defs', {}), 'Unbound local schema reference')
                self._validate(value, root['$defs'][name], root, depth + 1)
            else:
                identity, _, fragment = ref.partition('#')
                need(identity in self.schemas, 'Unbound external schema reference')
                target = self.schemas[identity]
                nested = target
                if fragment:
                    need(fragment.startswith('/$defs/') and fragment[7:] in target.get('$defs', {}),
                         'Unbound external schema fragment')
                    nested = target['$defs'][fragment[7:]]
                self._validate(value, nested, target, depth + 1)
        types = {'object': dict, 'array': list, 'string': str, 'integer': int,
                 'boolean': bool, 'null': type(None)}
        if 'type' in schema:
            need(schema['type'] in types and type(value) is types[schema['type']], 'JSON schema type differs')
        if 'const' in schema:
            need(equal(value, schema['const']), 'JSON schema constant differs')
        if 'enum' in schema:
            need(any(equal(value, item) for item in schema['enum']), 'JSON schema enum differs')
        if isinstance(value, dict):
            need(set(schema.get('required', [])) <= set(value), 'Required JSON field absent')
            props = schema.get('properties', {})
            if schema.get('additionalProperties') is False:
                need(set(value) <= set(props), 'Unknown JSON field')
            for key in set(value) & set(props):
                self._validate(value[key], props[key], root, depth + 1)
        if isinstance(value, list):
            need(schema.get('minItems', 0) <= len(value) <= schema.get('maxItems', len(value)), 'JSON array length differs')
            if schema.get('uniqueItems'):
                serialized = [json.dumps(item, sort_keys=True, ensure_ascii=False) for item in value]
                need(len(serialized) == len(set(serialized)), 'Duplicate JSON array member')
            if 'items' in schema:
                for item in value:
                    self._validate(item, schema['items'], root, depth + 1)
        if isinstance(value, str):
            need(schema.get('minLength', 0) <= len(value) <= schema.get('maxLength', len(value)), 'JSON string length differs')
            if 'pattern' in schema:
                need(re.search(schema['pattern'], value) is not None, 'JSON string pattern differs')
        if type(value) is int:
            need(schema.get('minimum', value) <= value <= schema.get('maximum', value), 'JSON integer range differs')
        if 'oneOf' in schema:
            need(sum(valid(child) for child in schema['oneOf']) == 1, 'JSON oneOf differs')
        if 'anyOf' in schema:
            need(any(valid(child) for child in schema['anyOf']), 'JSON anyOf differs')
        for child in schema.get('allOf', []):
            self._validate(value, child, root, depth + 1)
        if 'not' in schema:
            need(not valid(schema['not']), 'JSON not differs')
        if 'if' in schema:
            selected = 'then' if valid(schema['if']) else 'else'
            if selected in schema:
                self._validate(value, schema[selected], root, depth + 1)
