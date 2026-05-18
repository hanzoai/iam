// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// @ts-nocheck
import React from "react";
import {ChevronDown} from "lucide-react";
import {Popover, PopoverContent, PopoverTrigger} from "../components/ui/popover";
import {Input} from "../components/ui/input";
import {Spinner} from "../components/ui/spinner";
import {cn} from "../lib/utils";
import * as Setting from "../Setting";

const SCROLL_BOTTOM_OFFSET = 20;

const defaultOptionMapper = (item) => {
  if (item === null) {
    return null;
  }
  if (typeof item === "string") {
    return Setting.getOption(item, item);
  }
  const value = item.value ?? item.name ?? item.id ?? item.key;
  const label = item.label ?? item.displayName ?? value;
  if (value === undefined) {
    return null;
  }
  return Setting.getOption(label, value);
};

function PaginateSelect(props) {
  const {
    fetchPage,
    buildFetchArgs,
    optionMapper = defaultOptionMapper,
    pageSize = Setting.MAX_PAGE_SIZE,
    debounceMs = Setting.SEARCH_DEBOUNCE_MS,
    onError,
    onSearch: onSearchProp,
    onPopupScroll: onPopupScrollProp,
    showSearch = true,
    notFoundContent,
    loading: selectLoading,
    reloadKey,
    value,
    onChange,
    placeholder,
    disabled,
    className,
    style,
  } = props;

  const [options, setOptions] = React.useState([]);
  const [hasMore, setHasMore] = React.useState(true);
  const [loading, setLoading] = React.useState(false);
  const [open, setOpen] = React.useState(false);
  const [searchText, setSearchText] = React.useState("");

  const debounceRef = React.useRef(null);
  const latestSearchRef = React.useRef("");
  const loadingRef = React.useRef(false);
  const requestIdRef = React.useRef(0);
  const pageRef = React.useRef(0);
  const fetchPageRef = React.useRef(fetchPage);
  const buildFetchArgsRef = React.useRef(buildFetchArgs);
  const optionMapperRef = React.useRef(optionMapper ?? defaultOptionMapper);

  React.useEffect(() => {
    fetchPageRef.current = fetchPage;
  }, [fetchPage]);

  React.useEffect(() => {
    buildFetchArgsRef.current = buildFetchArgs;
  }, [buildFetchArgs]);

  React.useEffect(() => {
    optionMapperRef.current = optionMapper ?? defaultOptionMapper;
  }, [optionMapper]);

  const handleError = React.useCallback((error) => {
    if (onError) {
      onError(error);
      return;
    }
    if (Setting?.showMessage) {
      Setting.showMessage("error", error?.message ?? String(error));
    }
  }, [onError]);

  const extractItems = React.useCallback((response) => {
    if (Array.isArray(response)) {
      return response;
    }
    if (Array.isArray(response?.items)) {
      return response.items;
    }
    if (Array.isArray(response?.data)) {
      return response.data;
    }
    if (Array.isArray(response?.list)) {
      return response.list;
    }
    return [];
  }, []);

  const mergeOptions = React.useCallback((prev, next, reset) => {
    if (reset) {
      return next;
    }

    const merged = [...prev];
    const indexByValue = new Map();
    merged.forEach((opt, idx) => {
      if (opt?.value !== undefined) {
        indexByValue.set(opt.value, idx);
      }
    });

    next.forEach((opt) => {
      if (!opt) {
        return;
      }
      const optionValue = opt.value;
      if (optionValue === undefined) {
        merged.push(opt);
        return;
      }
      if (indexByValue.has(optionValue)) {
        merged[indexByValue.get(optionValue)] = opt;
        return;
      }
      indexByValue.set(optionValue, merged.length);
      merged.push(opt);
    });

    return merged;
  }, []);

  const loadPage = React.useCallback(async({pageToLoad = 1, reset = false, search = latestSearchRef.current} = {}) => {
    const fetcher = fetchPageRef.current;
    if (typeof fetcher !== "function") {
      return;
    }
    if (loadingRef.current && !reset) {
      return;
    }
    if (reset) {
      loadingRef.current = false;
    }

    const currentRequestId = requestIdRef.current + 1;
    requestIdRef.current = currentRequestId;

    loadingRef.current = true;
    setLoading(true);

    const defaultArgsObject = {
      page: pageToLoad,
      pageSize,
      search,
      searchText: search,
      query: search,
    };

    try {
      const argsBuilder = buildFetchArgsRef.current;
      const builtArgs = argsBuilder ? argsBuilder({
        page: pageToLoad,
        pageSize,
        searchText: search,
      }) : defaultArgsObject;

      const payload = Array.isArray(builtArgs) ?
        await fetcher(...builtArgs) :
        await fetcher(builtArgs ?? defaultArgsObject);

      if (currentRequestId !== requestIdRef.current) {
        return;
      }

      if (payload?.status && payload.status !== "ok") {
        handleError(payload?.msg ?? payload?.error ?? "Request failed");
        setHasMore(false);
        return;
      }

      const items = extractItems(payload);
      const mapper = optionMapperRef.current ?? defaultOptionMapper;
      const mappedOptions = items.map(mapper).filter(Boolean);
      setOptions((prev) => mergeOptions(prev, mappedOptions, reset));
      pageRef.current = pageToLoad;

      const hasMoreFromPayload = typeof payload?.hasMore === "boolean" ? payload.hasMore : null;
      const hasMoreFromTotal = typeof payload?.total === "number" ? (pageToLoad * pageSize < payload.total) : null;
      const fallbackHasMore = mappedOptions.length === pageSize;
      setHasMore(hasMoreFromPayload ?? hasMoreFromTotal ?? fallbackHasMore);
    } catch (error) {
      if (currentRequestId === requestIdRef.current) {
        handleError(error);
      }
    } finally {
      if (currentRequestId === requestIdRef.current) {
        loadingRef.current = false;
        setLoading(false);
      }
    }
  }, [pageSize, extractItems, mergeOptions, handleError]);

  const resetAndLoad = React.useCallback((search = "") => {
    latestSearchRef.current = search;
    setOptions([]);
    setHasMore(true);
    pageRef.current = 0;
    loadPage({pageToLoad: 1, reset: true, search});
  }, [loadPage]);

  React.useEffect(() => {
    resetAndLoad("");
    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
      }
    };
  }, [resetAndLoad, reloadKey]);

  const handleSearch = React.useCallback((next) => {
    setSearchText(next);
    onSearchProp?.(next);
    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
    }

    const triggerSearch = () => resetAndLoad(next || "");

    if (!debounceMs) {
      triggerSearch();
      return;
    }

    debounceRef.current = setTimeout(triggerSearch, debounceMs);
  }, [debounceMs, onSearchProp, resetAndLoad]);

  const handleScroll = React.useCallback((event) => {
    onPopupScrollProp?.(event);
    const target = event?.target;
    if (!target || loadingRef.current || !hasMore) {
      return;
    }

    const reachedBottom = target.scrollTop + target.offsetHeight >= target.scrollHeight - SCROLL_BOTTOM_OFFSET;
    if (reachedBottom) {
      const nextPage = pageRef.current + 1;
      loadPage({pageToLoad: nextPage});
    }
  }, [hasMore, loadPage, onPopupScrollProp]);

  const mergedLoading = selectLoading ?? loading;
  const selectedOption = options.find((o) => o?.value === value);
  const displayLabel = selectedOption?.label ?? value ?? "";

  const handleSelect = (opt) => {
    onChange?.(opt.value, opt);
    setOpen(false);
  };

  return (
    <Popover open={open && !disabled} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          disabled={disabled}
          className={cn(
            "flex h-10 w-full items-center justify-between rounded-md border border-input bg-background px-3 py-2 text-sm",
            "ring-offset-background focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2",
            "disabled:cursor-not-allowed disabled:opacity-50",
            className,
          )}
          style={style}
        >
          <span className={cn("truncate", !displayLabel && "text-muted-foreground")}>
            {displayLabel || placeholder || ""}
          </span>
          <ChevronDown className="h-4 w-4 opacity-50 ml-2" />
        </button>
      </PopoverTrigger>
      <PopoverContent
        className="p-0 w-[var(--radix-popover-trigger-width)]"
        align="start"
        sideOffset={4}
      >
        {showSearch && (
          <div className="p-2 border-b border-border">
            <Input
              value={searchText}
              onChange={(e) => handleSearch(e.target.value)}
              placeholder={placeholder || ""}
              className="h-8"
              autoFocus
            />
          </div>
        )}
        <div
          className="max-h-72 overflow-auto"
          onScroll={handleScroll}
        >
          {options.length === 0 && !mergedLoading && (
            <div className="px-3 py-4 text-center text-sm text-muted-foreground">
              {notFoundContent ?? "No data"}
            </div>
          )}
          {options.map((opt) => (
            <div
              key={String(opt.value)}
              role="option"
              aria-selected={opt.value === value}
              onClick={() => handleSelect(opt)}
              className={cn(
                "flex items-center px-3 py-2 text-sm cursor-pointer hover:bg-accent hover:text-accent-foreground",
                opt.value === value && "bg-accent text-accent-foreground",
              )}
            >
              {opt.label}
            </div>
          ))}
          {mergedLoading && (
            <div className="flex items-center justify-center py-2">
              <Spinner size="sm" />
            </div>
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}

export default PaginateSelect;
