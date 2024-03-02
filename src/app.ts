import fastify from 'fastify'
import cookie from '@fastify/Cookie'

import { transactionsRoutes } from './routes/transactions'

export const app = fastify()

app.register(cookie)
app.register(transactionsRoutes, {
  prefix: 'transactions',
})
