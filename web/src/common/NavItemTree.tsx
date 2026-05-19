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
      <div className="flex items-center gap-2 py-1" style={{paddingLeft: depth * 16}}>
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
          id={`nav-tree-${node.key}`}
        />
        <label
          htmlFor={`nav-tree-${node.key}`}
          className={cn("text-sm cursor-pointer select-none", disabled && "opacity-50 cursor-not-allowed")}
        >
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

export const NavItemTree = ({disabled, checkedKeys, defaultExpandedKeys, onCheck}) => {
  const NavItemNodes = [
    {
      title: i18next.t("general:All"),
      key: "all",
      children: [
        {
          title: i18next.t("general:Home"),
          key: "/home-top",
          children: [
            {title: i18next.t("general:Dashboard"), key: "/"},
            {title: i18next.t("general:Shortcuts"), key: "/shortcuts"},
            {title: i18next.t("general:Apps"), key: "/apps"},
          ],
        },
        {
          title: i18next.t("general:User Management"),
          key: "/orgs-top",
          children: [
            {title: i18next.t("general:Organizations"), key: "/organizations"},
            {title: i18next.t("general:Groups"), key: "/groups"},
            {title: i18next.t("general:Users"), key: "/users"},
            {title: i18next.t("general:Invitations"), key: "/invitations"},
          ],
        },
        {
          title: i18next.t("general:Identity"),
          key: "/applications-top",
          children: [
            {title: i18next.t("general:Applications"), key: "/applications"},
            {title: i18next.t("application:Providers"), key: "/providers"},
            {title: i18next.t("general:Resources"), key: "/resources"},
            {title: i18next.t("general:Certs"), key: "/certs"},
          ],
        },
        {
          title: i18next.t("general:Gateway"),
          key: "/sites-top",
          children: [
            {title: i18next.t("general:Certs"), key: "/certs"},
            {title: i18next.t("general:Rules"), key: "/rules"},
            {title: i18next.t("general:Sites"), key: "/sites"},
            {title: i18next.t("general:MCP Servers"), key: "/servers"},
          ],
        },
        {
          title: i18next.t("general:Authorization"),
          key: "/roles-top",
          children: [
            {title: i18next.t("general:Applications"), key: "/roles"},
            {title: i18next.t("general:Permissions"), key: "/permissions"},
            {title: i18next.t("general:Models"), key: "/models"},
            {title: i18next.t("general:Adapters"), key: "/adapters"},
            {title: i18next.t("general:Enforcers"), key: "/enforcers"},
          ],
        },
        {
          title: i18next.t("general:Logging & Auditing"),
          key: "/sessions-top",
          children: [
            {title: i18next.t("general:Sessions"), key: "/sessions"},
            {title: i18next.t("general:Records"), key: "/records"},
            {title: i18next.t("general:Tokens"), key: "/tokens"},
            {title: i18next.t("general:Verifications"), key: "/verifications"},
          ],
        },
        {
          title: i18next.t("general:Business & Payments"),
          key: "/business-top",
          children: [
            {title: i18next.t("general:Products"), key: "/products"},
            {title: i18next.t("general:Payments"), key: "/payments"},
            {title: i18next.t("general:Plans"), key: "/plans"},
            {title: i18next.t("general:Pricings"), key: "/pricings"},
            {title: i18next.t("general:Subscriptions"), key: "/subscriptions"},
            {title: i18next.t("general:Transactions"), key: "/transactions"},
          ],
        },
        {
          title: i18next.t("general:Admin"),
          key: "/admin-top",
          children: [
            {title: i18next.t("general:System Info"), key: "/sysinfo"},
            {title: i18next.t("general:Syncers"), key: "/syncers"},
            {title: i18next.t("general:Webhooks"), key: "/webhooks"},
            {title: i18next.t("general:Swagger"), key: "/swagger"},
          ],
        },
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
      {NavItemNodes.map((node) => (
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
