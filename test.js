/* global describe, it */

var expect = require('chai').expect
var generator = require('./')

describe('raml generator', function () {
  it('should compile a specification', function () {
    var generate = generator({
      templates: {
        out: '{{baseUri}}'
      }
    })

    expect(generate({
      baseUri: 'http://example.com'
    }).files.out).to.equal('http://example.com')
  })

  it('should iterate over resources', function () {
    var generate = generator({
      templates: {
        out: '{{#each allResources}}{{#each methods}}{{@key}}{{/each}}{{/each}}'
      }
    })

    expect(generate({
      resources: [{
        relativeUri: '/',
        methods: [
          { method: 'get' },
          { method: 'post' }
        ]
      }]
    }).files.out).to.equal('getpost')
  })

  it('should support partially conflicting top level resources', function () {
    var generate = generator({
      templates: {
        out: '{{#each allResources}}{{relativeUri}} {{originalRelativeUri}}\n{{/each}}'
      }
    })

    expect(generate({
      resources: [{
        relativeUri: '/test'
      }, {
        relativeUri: '/test/{id}'
      }, {
        relativeUri: '/test/{id}/test'
      }]
    }).files.out).to.equal([
      ' ',
      '/test /test',
      '/{0} /{id}',
      '/test /test',
      ''
    ].join('\n'))
  })

  it('should support absolute uris', function () {
    var generate = generator({
      templates: {
        out: '{{#each allResources}}{{absoluteUri}} {{originalAbsoluteUri}}\n{{/each}}'
      }
    })

    expect(generate({
      resources: [{
        relativeUri: '/test'
      }, {
        relativeUri: '/test/{id}'
      }, {
        relativeUri: '/test/{id}/test'
      }]
    }).files.out).to.equal([
      ' ',
      '/test /test',
      '/test/{0} /test/{id}',
      '/test/{0}/test /test/{id}/test',
      ''
    ].join('\n'))
  })

  describe('helpers', function () {
    describe('json', function () {
      it('should stringify', function () {
        var generate = generator({
          templates: {
            out: '{{json baseUri}}'
          }
        })

        expect(generate({
          baseUri: 'http://example.com'
        }).files.out).to.equal('"http://example.com"')
      })
    })
  })
})
