export default {
  routePrefix: '/documentation',
  exposeRoute: true,
  hideUntagged: true,
  swagger: {
    info: {
      title: 'Thorn API',
      description: 'A Friendly Remote Access Trojan',
      version: '1.0.0'
    },
    externalDocs: {
      url: 'https://github.com/fastify/fastify-swagger',
      description: 'Find more info here'
    },
    host: 'localhost:1337',
    schemes: ['http'],
    consumes: ['application/json'],
    produces: ['application/json'],
    components: {
      securitySchemes: {
          cookieAuth: {
          type: 'apiKey',
          in: 'cookie',
          name: 'admin_cookie'
        }
      }
    }
  }
}
