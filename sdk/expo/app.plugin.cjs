const { withGradleProperties, withPodfileProperties } = require('expo/config-plugins');
/** Autolinking supplies both pods and the Android library. No credentials/config data. */
module.exports = function withAppGuard(config) {
  config = withGradleProperties(config, config => {
    const properties = config.modResults.filter(p => p.type === 'property' && p.key === 'android.minSdkVersion');
    if (properties.length) {
      if (properties.some(p => !/^\d+$/.test(p.value))) throw new Error('APPGUARD_INVALID_MIN_SDK');
      const minimum = String(Math.max(26, ...properties.map(p => Number(p.value))));
      for (const property of properties) property.value = minimum;
    } else config.modResults.push({ type:'property', key:'android.minSdkVersion', value:'26' });
    return config;
  });
  return withPodfileProperties(config, config => {
    const current = config.modResults['ios.deploymentTarget'];
    if (current !== undefined && !/^\d+(\.\d+){0,2}$/.test(current)) throw new Error('APPGUARD_INVALID_IOS_TARGET');
    const components = (current ?? '0').split('.').map(Number);
    if (components[0] < 16 || (components[0] === 16 && (components[1] ?? 0) < 4)) config.modResults['ios.deploymentTarget'] = '16.4';
    return config;
  });
};
