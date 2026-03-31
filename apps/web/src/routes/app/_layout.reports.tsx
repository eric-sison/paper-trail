import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/app/_layout/reports')({
  component: RouteComponent,
})

function RouteComponent() {
  return <div>Hello "/app/_layout/reports"!</div>
}
