export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[]

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.1"
  }
  public: {
    Tables: {
      branding_settings: {
        Row: {
          accent_color: string
          app_name: string
          app_subtitle: string
          created_at: string
          id: string
          logo_url: string | null
          primary_color: string
          updated_at: string
        }
        Insert: {
          accent_color?: string
          app_name?: string
          app_subtitle?: string
          created_at?: string
          id?: string
          logo_url?: string | null
          primary_color?: string
          updated_at?: string
        }
        Update: {
          accent_color?: string
          app_name?: string
          app_subtitle?: string
          created_at?: string
          id?: string
          logo_url?: string | null
          primary_color?: string
          updated_at?: string
        }
        Relationships: []
      }
      oidc_providers: {
        Row: {
          client_id: string
          client_secret: string
          created_at: string
          display_name: string
          enabled: boolean
          id: string
          issuer_url: string
          name: string
          scopes: string
          updated_at: string
        }
        Insert: {
          client_id: string
          client_secret: string
          created_at?: string
          display_name?: string
          enabled?: boolean
          id?: string
          issuer_url: string
          name?: string
          scopes?: string
          updated_at?: string
        }
        Update: {
          client_id?: string
          client_secret?: string
          created_at?: string
          display_name?: string
          enabled?: boolean
          id?: string
          issuer_url?: string
          name?: string
          scopes?: string
          updated_at?: string
        }
        Relationships: []
      }
      profiles: {
        Row: {
          created_at: string
          email: string | null
          full_name: string | null
          id: string
          updated_at: string
        }
        Insert: {
          created_at?: string
          email?: string | null
          full_name?: string | null
          id: string
          updated_at?: string
        }
        Update: {
          created_at?: string
          email?: string | null
          full_name?: string | null
          id?: string
          updated_at?: string
        }
        Relationships: []
      }
      tool_versions: {
        Row: {
          created_at: string
          cves: Json
          cycle_label: string | null
          eol: string | null
          id: string
          is_outdated: boolean | null
          is_patch_outdated: boolean | null
          latest_patch_for_cycle: string | null
          latest_version: string | null
          lts: string | null
          tool_id: string
          updated_at: string
          version: string
        }
        Insert: {
          created_at?: string
          cves?: Json
          cycle_label?: string | null
          eol?: string | null
          id?: string
          is_outdated?: boolean | null
          is_patch_outdated?: boolean | null
          latest_patch_for_cycle?: string | null
          latest_version?: string | null
          lts?: string | null
          tool_id: string
          updated_at?: string
          version: string
        }
        Update: {
          created_at?: string
          cves?: Json
          cycle_label?: string | null
          eol?: string | null
          id?: string
          is_outdated?: boolean | null
          is_patch_outdated?: boolean | null
          latest_patch_for_cycle?: string | null
          latest_version?: string | null
          lts?: string | null
          tool_id?: string
          updated_at?: string
          version?: string
        }
        Relationships: [
          {
            foreignKeyName: "tool_versions_tool_id_fkey"
            columns: ["tool_id"]
            isOneToOne: false
            referencedRelation: "tools"
            referencedColumns: ["id"]
          },
        ]
      }
      tools: {
        Row: {
          created_at: string
          cves: Json
          cycle_label: string | null
          eol: string | null
          id: string
          is_outdated: boolean | null
          is_patch_outdated: boolean | null
          latest_patch_for_cycle: string | null
          latest_version: string | null
          lts: string | null
          name: string
          source_url: string | null
          updated_at: string
          user_id: string
          version: string
        }
        Insert: {
          created_at?: string
          cves?: Json
          cycle_label?: string | null
          eol?: string | null
          id?: string
          is_outdated?: boolean | null
          is_patch_outdated?: boolean | null
          latest_patch_for_cycle?: string | null
          latest_version?: string | null
          lts?: string | null
          name: string
          source_url?: string | null
          updated_at?: string
          user_id: string
          version: string
        }
        Update: {
          created_at?: string
          cves?: Json
          cycle_label?: string | null
          eol?: string | null
          id?: string
          is_outdated?: boolean | null
          is_patch_outdated?: boolean | null
          latest_patch_for_cycle?: string | null
          latest_version?: string | null
          lts?: string | null
          name?: string
          source_url?: string | null
          updated_at?: string
          user_id?: string
          version?: string
        }
        Relationships: []
      }
      user_roles: {
        Row: {
          id: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Insert: {
          id?: string
          role: Database["public"]["Enums"]["app_role"]
          user_id: string
        }
        Update: {
          id?: string
          role?: Database["public"]["Enums"]["app_role"]
          user_id?: string
        }
        Relationships: []
      }
    }
    Views: {
      oidc_providers_public: {
        Row: {
          client_id: string | null
          display_name: string | null
          enabled: boolean | null
          id: string | null
          issuer_url: string | null
          name: string | null
          scopes: string | null
        }
        Insert: {
          client_id?: string | null
          display_name?: string | null
          enabled?: boolean | null
          id?: string | null
          issuer_url?: string | null
          name?: string | null
          scopes?: string | null
        }
        Update: {
          client_id?: string | null
          display_name?: string | null
          enabled?: boolean | null
          id?: string | null
          issuer_url?: string | null
          name?: string | null
          scopes?: string | null
        }
        Relationships: []
      }
    }
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"]
          _user_id: string
        }
        Returns: boolean
      }
    }
    Enums: {
      app_role: "admin" | "user"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] &
        DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] &
        DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof DatabaseWithoutInternals },
  EnumName extends DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      app_role: ["admin", "user"],
    },
  },
} as const
