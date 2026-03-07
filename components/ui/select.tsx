import { SelectHTMLAttributes } from 'react';
import { cn } from '@/lib/utils';

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={cn('h-9 w-full rounded-md border border-border bg-bg px-2 text-sm text-text outline-none focus:ring-1 focus:ring-accent', className)} {...props} />;
}
