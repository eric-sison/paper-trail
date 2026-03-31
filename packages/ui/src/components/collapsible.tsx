import { Collapsible as CollapsiblePrimitive } from "@base-ui/react/collapsible";
import { cn } from "../lib/utils";

function Collapsible({ ...props }: CollapsiblePrimitive.Root.Props) {
  return <CollapsiblePrimitive.Root data-slot="collapsible" {...props} />;
}

function CollapsibleTrigger({ ...props }: CollapsiblePrimitive.Trigger.Props) {
  return <CollapsiblePrimitive.Trigger data-slot="collapsible-trigger" {...props} />;
}

function CollapsibleContent({ className, ...props }: CollapsiblePrimitive.Panel.Props) {
  return (
    <CollapsiblePrimitive.Panel
      data-slot="collapsible-content"
      className={cn(
        "flex h-(--collapsible-panel-height) flex-col justify-end overflow-hidden text-sm",
        "transition-all duration-150 ease-out",
        "data-ending-style:h-0 data-starting-style:h-0",
        className
      )}
      {...props}
    />
  );
}

export { Collapsible, CollapsibleTrigger, CollapsibleContent };
