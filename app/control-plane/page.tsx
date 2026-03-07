'use client';

import { Card } from '@/components/ui/card';

export default function ControlPlanePage() {
  return <div className="grid gap-2 lg:grid-cols-2"><Card className="p-3 text-xs">Endpoint Inventory & posture matrix</Card><Card className="p-3 text-xs">Vulnerability queue and remediation states</Card></div>;
}
