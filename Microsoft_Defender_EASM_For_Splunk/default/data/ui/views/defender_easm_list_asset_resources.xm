<!--
  File: defender_easm_list_asset_resources.xml
  Microsoft Defender EASM for Splunk App

  Purpose:
  Canonical inventory view mapped 1:1 to the
  Assets – List Asset Resource (data-plane) API.

  Source:
  GET /assets
-->

<dashboard version="1.1">
  <label>Asset Resources</label>

  <description>
    Canonical inventory of all asset resources discovered by Microsoft Defender
    External Attack Surface Management. This dashboard maps directly to the
    Assets – List Asset Resource API and represents the authoritative asset catalog.
  </description>

  <!-- ========================= -->
  <!-- TIME PICKER -->
  <!-- ========================= -->
  <fieldset submitButton="false">
    <input type="time" token="time">
      <label>Time Range</label>
      <default>
        <earliest>-30d@d</earliest>
        <latest>now</latest>
      </default>
    </input>

    <input type="dropdown" token="asset_type">
      <label>Asset Type</label>
      <choice value="*">All</choice>
      <search>
        <query>
          `easm_index`
          sourcetype=defender:easm:asset
          | stats count by asset_type
          | sort asset_type
        </query>
      </search>
      <fieldForLabel>asset_type</fieldForValue>asset_type</fieldForValue>
    </input>
  </fieldset>

  <!-- ========================= -->
  <!-- KPI SUMMARY -->
  <!-- ========================= -->
  <row>
    <panel>
      <title>Total Assets</title>
      <single>
        <search>
          <query>
            `easm_index`
            sourcetype=defender:easm:asset
            asset_type=$asset_type$
            | stats count
          </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
      </single>
    </panel>

    <panel>
      <title>Asset Types</title>
      <single>
        <search>
          <query>
            `easm_index`
            sourcetype=defender:easm:asset
            | stats dc(asset_type)
          </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
      </single>
    </panel>

    <panel>
      <title>Active Assets</title>
      <single>
        <search>
          <query>
            `easm_index`
            sourcetype=defender:easm:asset
            state=Active
            asset_type=$asset_type$
            | stats count
          </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
      </single>
    </panel>
  </row>

  <!-- ========================= -->
  <!-- ASSET TYPE DISTRIBUTION -->
  <!-- ========================= -->
  <row>
    <panel>
      <title>Assets by Type</title>
      <chart>
        <search>
          <query>
            `easm_index`
            sourcetype=defender:easm:asset
            | stats count by asset_type
            | sort - count
          </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="charting.chart">bar</option>
        <option name="charting.axisTitleX.text">Asset Type</option>
        <option name="charting.axisTitleY.text">Count</option>
        <option name="charting.legend.placement">none</option>
      </chart>
    </panel>
  </row>

  <!-- ========================= -->
  <!-- ASSET INVENTORY TABLE -->
  <!-- ========================= -->
  <row>
    <panel>
      <title>Asset Inventory</title>
      <table>
        <search>
          <query>
            `easm_index`
            sourcetype=defender:easm:asset
            asset_type=$asset_type$
            | table
                _time
                easm_id
                asset_type
                name
                state
                discovery_source
                first_seen
                last_seen
            | sort - last_seen
          </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>

        <option name="count">25</option>
        <option name="wrap">true</option>
        <option name="rowNumbers">true</option>
      </table>
    </panel>
  </row>

  <!-- ========================= -->
  <!-- RAW EVENT VIEW -->
  <!-- ========================= -->
  <row>
    <panel>
      <title>Raw Asset Event</title>
      <event>
        <search>
          <query>
            `easm_index`
            sourcetype=defender:easm:asset
            asset_type=$asset_type$
          </query>
          <earliest>$time.earliest$</earliest>
          <latest>$time.latest$</latest>
        </search>
        <option name="count">5</option>
        <option name="wrap">true</option>
      </event>
    </panel>
  </row>

</dashboard>
