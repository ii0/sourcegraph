import deepEqual from 'deep-equal'
import { isErrorLike } from './errors'
import { parseJSONCOrError } from './util'

describe('parseJSONCOrError', () => {
    it('parses valid JSON', () => deepEqual(parseJSONCOrError('{"a":1}'), { a: 1 }))
    it('parses valid JSONC', () => deepEqual(parseJSONCOrError('{/*x*/"a":1,}'), { a: 1 }))
    it('returns an error value for invalid input', () => {
        const value = parseJSONCOrError('.')
        assert.ok(isErrorLike(value))
    })
})
