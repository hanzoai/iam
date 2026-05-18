// @ts-nocheck
import i18next from "i18next";
import React from "react";
import {Checkbox} from "../components/ui/checkbox";
import {cn} from "../lib/utils";

// TODO(rip-antd): replaced antd <Tree> with simple recursive checkbox tree.
// Re-evaluate if we need keyboard nav / virtualization / drag-drop later.

const collectKeys = (nodes) => {
  const out = [];
  nodes.forEach((n) => {
    out.push(n.key);
    if (n.children) {
      out.push(...collectKeys(n.children));
    }
  });
  return out;
};

const TreeNode = ({node, checked, expanded, disabled, onToggleCheck, onToggleExpand, depth = 0}) => {
  const hasChildren = Array.isArray(node.children) && node.children.length > 0;
  const isExpanded = expanded.has(node.key);
  const isChecked = checked.has(node.key);

  return (
    <li className="list-none">
      <div className={cn("flex items-center gap-2 py-1")} style={{paddingLeft: depth * 16}}>
        {hasChildren ? (
          <button
            type="button"
            className="w-4 h-4 inline-flex items-center justify-center text-xs text-muted-foreground hover:text-foreground"
            onClick={() => onToggleExpand(node.key)}
            aria-label={isExpanded ? "collapse" : "expand"}
          >
            {isExpanded ? "▾" : "▸"}
          </button>
        ) : (
          <span className="w-4 h-4 inline-block" />
        )}
        <Checkbox
          checked={isChecked}
          disabled={disabled}
          onCheckedChange={() => onToggleCheck(node)}
          id={`tree-${node.key}`}
        />
        <label htmlFor={`tree-${node.key}`} className={cn("text-sm cursor-pointer select-none", disabled && "opacity-50 cursor-not-allowed")}>
          {node.title}
        </label>
      </div>
      {hasChildren && isExpanded && (
        <ul className="pl-0">
          {node.children.map((child) => (
            <TreeNode
              key={child.key}
              node={child}
              checked={checked}
              expanded={expanded}
              disabled={disabled}
              onToggleCheck={onToggleCheck}
              onToggleExpand={onToggleExpand}
              depth={depth + 1}
            />
          ))}
        </ul>
      )}
    </li>
  );
};

export const WidgetItemTree = ({disabled, checkedKeys, defaultExpandedKeys, onCheck}) => {
  const WidgetItemNodes = [
    {
      title: i18next.t("general:All"),
      key: "all",
      children: [
        {title: i18next.t("general:Tour"), key: "tour"},
        {title: i18next.t("general:AI Assistant"), key: "ai-assistant"},
        {title: i18next.t("user:Language"), key: "language"},
        {title: i18next.t("theme:Theme"), key: "theme"},
      ],
    },
  ];

  const checked = React.useMemo(
    () => new Set(Array.isArray(checkedKeys) ? checkedKeys : (checkedKeys?.checked ?? [])),
    [checkedKeys],
  );
  const [expanded, setExpanded] = React.useState(() => new Set(defaultExpandedKeys ?? []));

  const handleToggleCheck = (node) => {
    const next = new Set(checked);
    const keys = [node.key, ...(node.children ? collectKeys(node.children) : [])];
    const allChecked = keys.every((k) => next.has(k));
    keys.forEach((k) => {
      if (allChecked) {
        next.delete(k);
      } else {
        next.add(k);
      }
    });
    onCheck?.(Array.from(next), {checked: Array.from(next), node});
  };

  const handleToggleExpand = (key) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  return (
    <ul className="pl-0 m-0">
      {WidgetItemNodes.map((node) => (
        <TreeNode
          key={node.key}
          node={node}
          checked={checked}
          expanded={expanded}
          disabled={disabled}
          onToggleCheck={handleToggleCheck}
          onToggleExpand={handleToggleExpand}
        />
      ))}
    </ul>
  );
};
