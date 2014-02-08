package com.ricardolorenzo.identity.script;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import com.ricardolorenzo.identity.IdentityException;

public class ScriptCollection {
    public static final String FIELD_LAST_MODIFIED = "@lastmodified@";
    public static final String FIELD_MATCH = "@match@";

    public static final String USER_ADD = "user_add";
    public static final String USER_DELETE = "user_delete";
    public static final String USER_READ = "user_read";
    public static final String USER_SEARCH = "user_search";
    public static final String USER_SEARCH_MODIFIED = "user_search_modified";
    public static final String USER_UPDATE = "user_update";
    public static final String GROUP_ADD = "group_add";
    public static final String GROUP_DELETE = "group_delete";
    public static final String GROUP_READ = "group_read";
    public static final String GROUP_SEARCH = "group_search";
    public static final String GROUP_UPDATE = "group_update";
    private Map<String, String> scripts;

    public ScriptCollection() {
        this.scripts = new HashMap<String, String>();
    }

    public ScriptCollection(final Properties scriptProperties) throws IdentityException {
        this();
        for (Entry<Object, Object> e : scriptProperties.entrySet()) {
            String type = String.valueOf(e.getKey());
            if (!isValidScriptType(type)) {
                throw new IdentityException("invalid script type [" + type + "]");
            }
            this.scripts.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
        }
    }

    public String getScript(final String type) throws IdentityException {
        if (!isValidScriptType(type)) {
            throw new IdentityException("invalid script type [" + type + "]");
        }
        return this.scripts.get(type);
    }

    public boolean hasScript(final String type) throws IdentityException {
        if (!isValidScriptType(type)) {
            throw new IdentityException("invalid script type [" + type + "]");
        }
        return this.scripts.containsKey(type);
    }

    public boolean isValidScriptType(String type) {
        switch (type) {
            case USER_ADD: {
                return true;
            }
            case USER_DELETE: {
                return true;
            }
            case USER_READ: {
                return true;
            }
            case USER_SEARCH: {
                return true;
            }
            case USER_SEARCH_MODIFIED: {
                return true;
            }
            case USER_UPDATE: {
                return true;
            }
            case GROUP_ADD: {
                return true;
            }
            case GROUP_DELETE: {
                return true;
            }
            case GROUP_READ: {
                return true;
            }
            case GROUP_SEARCH: {
                return true;
            }
            case GROUP_UPDATE: {
                return true;
            }
            default: {
                return false;
            }
        }
    }

    public void setScript(String type, String content) throws IdentityException {
        if (!isValidScriptType(type)) {
            throw new IdentityException("invalid script type [" + type + "]");
        }
        this.scripts.put(type, content);
    }
}
