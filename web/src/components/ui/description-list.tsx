"use client"

import * as React from "react"
import { cn } from "../../lib/utils"

interface DescriptionItem {
  label: React.ReactNode
  value: React.ReactNode
  span?: number
}

interface DescriptionListProps extends React.HTMLAttributes<HTMLDListElement> {
  items: DescriptionItem[]
  columns?: 1 | 2 | 3 | 4
  bordered?: boolean
}

const columnClasses = {
  1: "grid-cols-1",
  2: "grid-cols-1 sm:grid-cols-2",
  3: "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3",
  4: "grid-cols-1 sm:grid-cols-2 lg:grid-cols-4",
}

const spanClasses: Record<number, string> = {
  1: "sm:col-span-1",
  2: "sm:col-span-2",
  3: "sm:col-span-3",
  4: "sm:col-span-4",
}

const DescriptionList = React.forwardRef<HTMLDListElement, DescriptionListProps>(
  ({ className, items, columns = 2, bordered = false, ...props }, ref) => {
    return (
      <dl
        ref={ref}
        className={cn(
          "grid gap-4",
          columnClasses[columns],
          bordered && "divide-y divide-border",
          className
        )}
        {...props}
      >
        {items.map((item, index) => (
          <div
            key={index}
            className={cn(
              "flex flex-col gap-1",
              bordered && "py-3 first:pt-0",
              item.span && spanClasses[item.span]
            )}
          >
            <dt className="text-sm font-medium text-muted-foreground">{item.label}</dt>
            <dd className="text-sm text-foreground">{item.value ?? "-"}</dd>
          </div>
        ))}
      </dl>
    )
  }
)
DescriptionList.displayName = "DescriptionList"

export { DescriptionList }
export type { DescriptionItem, DescriptionListProps }
