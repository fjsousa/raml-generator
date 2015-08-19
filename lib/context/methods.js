var pick = require('object.pick')
var sanitizeParameters = require('./parameters')

/**
 * Sanitize a method into a flatter, more readable structure.
 *
 * @param  {Object} method
 * @param  {Object} resource
 * @param  {Object} spec
 * @return {Object}
 */
var sanitizeMethod = function (method, resource, spec) {
  // Pick only the usable properties.
  var obj = pick(method, [
    'method',
    'protocols',
    'responses',
    'body',
    'headers'
  ])

  // Attach a unique id to every method.
  obj.id = spec.format.uniqueId('method')
  obj.resource = resource
  obj.queryParameters = sanitizeParameters(method.queryParameters)
  obj.description = (method.description || '').trim()
  obj.displayName = (method.displayName || '').trim()

  //supporting Oauth2 roles only
  if (method.securedBy && method.securedBy[0].OAuth2.roles){

    obj.queryParameters.access_token = {
      default: '',
      description: 'Roles supported: <ul>' + method.securedBy[0].OAuth2.roles.map(function(role){return '<li>' + role + '</li>' }).join('') + '</ul>',
      displayName: 'access_token',
      required: false,
      type: 'string'
    }
  }

  // TODO: Add `securedBy` support.
  // TODO: Automatically infer content-type header from body.

  return obj
}

/**
 * Sanitize a methods array into a more reusable object.
 *
 * @param  {Array}  methods
 * @param  {Object} resource
 * @param  {Object} spec
 * @return {Object}
 */
module.exports = function (methods, resource, spec) {
  var obj = {}

  if (!methods) {
    return obj
  }

  methods.forEach(function (method) {
    var verb = method.method
    var sanitizedMethod = sanitizeMethod(method, resource, spec)

    obj[verb] = sanitizedMethod
    sanitizedMethod.key = verb
  })

  return obj
}
